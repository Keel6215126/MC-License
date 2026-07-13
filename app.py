from __future__ import annotations

import hmac
import os
import secrets
import shutil
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from flask import Flask, after_this_request, jsonify, render_template, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from discord_webhook import DiscordWebhookConfig, WebhookDeliveryError, send_uploaded_file

from license_injector import (
    LicenseInjectionError,
    run_license_injection,
    validate_protected_jar,
)
from obfuscator import (
    ObfuscationError,
    build_bundle,
    engine_display_name,
    get_engine_status,
    normalize_engine,
    run_obfuscation,
    safe_extract_library_zip,
)


BASE_DIR = Path(__file__).resolve().parent
JOB_ROOT = Path(os.environ.get("JOB_ROOT", "/tmp/plugin-protector/jobs")).resolve()
JOB_ROOT.mkdir(parents=True, exist_ok=True)
MCL_DEPENDENCY_DIR = Path(os.environ.get("MCL_DEPENDENCY_DIR", BASE_DIR / "vendor")).resolve()
MAX_UPLOAD_MB = max(1, int(os.environ.get("MAX_UPLOAD_MB", "100")))
JOB_TTL_SECONDS = max(300, int(os.environ.get("JOB_TTL_MINUTES", "60")) * 60)
TIMEOUT_SECONDS = max(30, int(os.environ.get("OBFUSCATION_TIMEOUT_SECONDS", "240")))
LICENSE_TIMEOUT_SECONDS = max(10, int(os.environ.get("LICENSE_TIMEOUT_SECONDS", "45")))
MAX_PARALLEL_JOBS = max(1, min(4, int(os.environ.get("MAX_PARALLEL_JOBS", "1"))))
MAX_QUEUED_JOBS = max(MAX_PARALLEL_JOBS, int(os.environ.get("MAX_QUEUED_JOBS", "20")))
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
DISCORD_WEBHOOK_REQUIRED = os.environ.get("DISCORD_WEBHOOK_REQUIRED", "true").strip().lower() not in {"0", "false", "no", "off"}
DISCORD_WEBHOOK = DiscordWebhookConfig(
    url=os.environ.get("DISCORD_WEBHOOK_URL", "").strip(),
    username=os.environ.get("DISCORD_WEBHOOK_USERNAME", "Plugin Protector Uploads").strip() or "Plugin Protector Uploads",
    avatar_url=os.environ.get("DISCORD_WEBHOOK_AVATAR_URL", "").strip(),
    timeout_seconds=max(5, int(os.environ.get("DISCORD_WEBHOOK_TIMEOUT_SECONDS", "30"))),
    max_attempts=max(1, min(5, int(os.environ.get("DISCORD_WEBHOOK_MAX_ATTEMPTS", "3")))),
    max_file_bytes=max(1, int(os.environ.get("DISCORD_WEBHOOK_MAX_FILE_MB", "10"))) * 1024 * 1024,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

executor = ThreadPoolExecutor(max_workers=MAX_PARALLEL_JOBS, thread_name_prefix="protector")
jobs: dict[str, dict[str, Any]] = {}
jobs_lock = threading.RLock()


def now() -> float:
    return time.time()


def verify_access_key(provided: str) -> bool:
    if not APP_PASSWORD:
        return True
    return hmac.compare_digest(APP_PASSWORD, provided or "")


def verify_token(job: dict[str, Any], token: str) -> bool:
    expected = str(job.get("token", ""))
    return bool(expected and token and hmac.compare_digest(expected, token))


def update_job(job_id: str, **changes: Any) -> None:
    with jobs_lock:
        if job_id in jobs:
            jobs[job_id].update(changes)


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "id", "workflow", "status", "filename", "mode", "engine", "engine_name", "message", "error",
        "created_at", "started_at", "finished_at", "frameworks", "entry_classes",
        "renamed_class_count", "elapsed_seconds", "jar_download", "bundle_download",
        "license_original_main", "license_wrapper_main", "license_library_classes",
    }
    return {key: value for key, value in job.items() if key in allowed and value is not None}


def create_output_name(original: str, workflow: str, engine: str = "proguard") -> str:
    clean = secure_filename(original) or "uploaded.jar"
    stem = Path(clean).stem[:100] or "uploaded"
    suffix = "Protected" if workflow == "protect" else "Obfuscated"
    engine_suffix = {"proguard": "ProGuard", "skid": "SkidHybrid", "yguard": "yGuard"}[normalize_engine(engine)]
    return f"{stem}-{suffix}-{engine_suffix}.jar"


def save_upload(file_storage: Any, destination: Path) -> None:
    file_storage.save(destination)
    if destination.stat().st_size == 0:
        raise ObfuscationError(f"{file_storage.filename or 'Upload'} was empty.")


def require_webhook() -> None:
    if DISCORD_WEBHOOK_REQUIRED and not DISCORD_WEBHOOK.configured:
        raise WebhookDeliveryError(
            "File processing is disabled until DISCORD_WEBHOOK_URL is configured in Railway."
        )


def forward_upload(destination: Path, original_filename: str, workflow: str, upload_kind: str, upload_id: str) -> None:
    if not DISCORD_WEBHOOK.configured:
        if DISCORD_WEBHOOK_REQUIRED:
            require_webhook()
        return
    send_uploaded_file(
        config=DISCORD_WEBHOOK,
        file_path=destination,
        original_filename=original_filename,
        workflow=workflow,
        upload_kind=upload_kind,
        upload_id=upload_id,
    )


def save_libraries(job_dir: Path, workflow: str, upload_id: str) -> list[Path]:
    library_dir = job_dir / "libraries"
    library_dir.mkdir(exist_ok=True)
    libraries: list[Path] = []
    for index, upload in enumerate(request.files.getlist("libraries"), start=1):
        if not upload or not upload.filename:
            continue
        clean = secure_filename(upload.filename) or f"library-{index}"
        lower = clean.lower()
        if not (lower.endswith(".jar") or lower.endswith(".zip")):
            raise ObfuscationError(f"Unsupported dependency file: {clean}")
        destination = library_dir / f"upload-{index}-{clean}"
        save_upload(upload, destination)
        forward_upload(destination, upload.filename, workflow, "dependency", upload_id)
        if lower.endswith(".jar"):
            try:
                with zipfile.ZipFile(destination, "r") as archive:
                    if not any(name.endswith(".class") for name in archive.namelist()):
                        raise ObfuscationError(f"Dependency {clean} contains no class files.")
            except zipfile.BadZipFile as exc:
                raise ObfuscationError(f"Dependency {clean} is not a valid JAR.") from exc
            libraries.append(destination)
        else:
            extracted_dir = library_dir / f"extracted-{index}"
            libraries.extend(safe_extract_library_zip(destination, extracted_dir))
    return libraries


def process_job(job_id: str) -> None:
    with jobs_lock:
        job = dict(jobs[job_id])
    job_dir = Path(job["job_dir"])
    input_jar = Path(job["input_jar"])
    output_name = job["output_name"]
    workflow = job["workflow"]
    mode = job["mode"]
    engine = job.get("engine", "proguard")
    engine_name = engine_display_name(engine)
    libraries = [Path(value) for value in job.get("libraries", [])]

    update_job(job_id, status="running", message="Preparing the JAR…", started_at=now())
    try:
        source_jar = input_jar
        license_result = None
        if workflow == "protect":
            update_job(job_id, message="Adding the mandatory MC License check…")
            source_jar = job_dir / "licensed-stage.jar"
            license_result = run_license_injection(
                input_jar=input_jar,
                output_jar=source_jar,
                plugin_id=job["plugin_id"],
                dependency_dir=MCL_DEPENDENCY_DIR,
                timeout_seconds=LICENSE_TIMEOUT_SECONDS,
            )
            update_job(job_id, message=f"MC License added. {engine_name} is obfuscating the protected JAR…")
        else:
            update_job(job_id, message=f"{engine_name} is processing the JAR…")

        result = run_obfuscation(
            input_jar=source_jar,
            work_dir=job_dir,
            output_name=output_name,
            mode=mode,
            library_jars=libraries,
            timeout_seconds=TIMEOUT_SECONDS,
            engine=engine,
        )
        if workflow == "protect":
            validate_protected_jar(result.output_jar, result.mapping_file)

        bundle_path = build_bundle(result, job_dir / f"{Path(output_name).stem}-Bundle.zip")
        token = job["token"]
        changes: dict[str, Any] = {
            "status": "complete",
            "engine": engine,
            "engine_name": engine_name,
            "message": "Protection completed and the final JAR passed validation." if workflow == "protect" else "Obfuscation completed and the output passed validation.",
            "finished_at": now(),
            "frameworks": result.inspection.frameworks,
            "entry_classes": result.mapped_entry_classes,
            "renamed_class_count": result.renamed_class_count,
            "elapsed_seconds": round(result.elapsed_seconds, 2),
            "output_jar": str(result.output_jar),
            "bundle_path": str(bundle_path),
            "jar_download": f"/download/{job_id}/jar?token={token}",
            "bundle_download": f"/download/{job_id}/bundle?token={token}",
        }
        if license_result:
            changes.update({
                "license_original_main": license_result.original_main,
                "license_wrapper_main": license_result.wrapper_main,
                "license_library_classes": license_result.library_classes,
            })
        update_job(job_id, **changes)
    except Exception as exc:
        if isinstance(exc, (ObfuscationError, LicenseInjectionError)):
            message = str(exc)
        else:
            app.logger.exception("Unexpected job failure for %s", job_id)
            message = f"Unexpected server error: {exc}"
        update_job(job_id, status="failed", message="The build failed.", error=message[-12000:], finished_at=now())


def cleanup_loop() -> None:
    while True:
        cutoff = now() - JOB_TTL_SECONDS
        expired: list[tuple[str, str]] = []
        with jobs_lock:
            for job_id, job in list(jobs.items()):
                timestamp = job.get("finished_at") or job.get("created_at") or now()
                if timestamp < cutoff:
                    expired.append((job_id, job.get("job_dir", "")))
                    jobs.pop(job_id, None)
        for _, directory in expired:
            if directory:
                shutil.rmtree(directory, ignore_errors=True)
        time.sleep(60)


threading.Thread(target=cleanup_loop, name="job-cleaner", daemon=True).start()


@app.context_processor
def upload_forwarding_context():
    return {
        "upload_forwarding_enabled": DISCORD_WEBHOOK.configured,
        "upload_forwarding_required": DISCORD_WEBHOOK_REQUIRED,
        "discord_attachment_limit_mb": DISCORD_WEBHOOK.max_file_bytes // 1024 // 1024,
    }


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": f"Upload exceeds the {MAX_UPLOAD_MB} MB request limit."}), 413
    return render_template("error.html", message=f"Upload exceeds the {MAX_UPLOAD_MB} MB request limit."), 413


@app.get("/")
def home():
    return render_template("home.html")


@app.get("/license")
def license_page():
    return render_template("license.html", max_upload_mb=MAX_UPLOAD_MB, password_required=bool(APP_PASSWORD))


@app.get("/obfuscate")
def obfuscate_page():
    return render_template("obfuscate.html", max_upload_mb=MAX_UPLOAD_MB, password_required=bool(APP_PASSWORD))


@app.get("/protect")
def protect_page():
    return render_template("protect.html", max_upload_mb=MAX_UPLOAD_MB, password_required=bool(APP_PASSWORD))


@app.get("/license-check")
def license_check_page():
    return render_template("license_check.html")


@app.get("/health")
def health():
    dependencies_ready = MCL_DEPENDENCY_DIR.is_dir()
    webhook_ready = DISCORD_WEBHOOK.configured or not DISCORD_WEBHOOK_REQUIRED
    engine_status = get_engine_status()
    healthy = dependencies_ready and all(engine_status.values())
    return jsonify({
        "status": "ok" if healthy else "degraded",
        "version": "3.1.2",
        "jobs": len(jobs),
        "max_parallel_jobs": MAX_PARALLEL_JOBS,
        "mclicense_dependencies": dependencies_ready,
        "discord_webhook_configured": DISCORD_WEBHOOK.configured,
        "discord_webhook_required": DISCORD_WEBHOOK_REQUIRED,
        "uploads_enabled": webhook_ready,
        "obfuscation_engines": engine_status,
    }), 200 if healthy else 503


@app.post("/license/implement")
def implement_license():
    if not verify_access_key(request.form.get("access_key", "")):
        return render_template("error.html", message="Incorrect access key."), 401
    uploaded = request.files.get("jar")
    if not uploaded or not uploaded.filename:
        return render_template("error.html", message="Choose a JAR file first."), 400
    if not uploaded.filename.lower().endswith(".jar"):
        return render_template("error.html", message="The upload must use the .jar extension."), 400

    plugin_id = request.form.get("plugin_id", "").strip()
    if len(plugin_id) != 8 or not plugin_id.isalnum():
        return render_template("error.html", message="The MC License plugin ID must be exactly 8 letters and numbers."), 400
    try:
        require_webhook()
    except WebhookDeliveryError as exc:
        return render_template("error.html", message=str(exc)), 503
    upload_id = uuid.uuid4().hex
    request_dir = JOB_ROOT / f"license-{upload_id}"
    request_dir.mkdir(parents=True, exist_ok=False)
    input_jar = request_dir / "input.jar"
    output_name = f"{Path(secure_filename(uploaded.filename) or 'plugin.jar').stem[:100]}-MC-Licensed.jar"
    output_jar = request_dir / output_name
    try:
        save_upload(uploaded, input_jar)
        forward_upload(input_jar, uploaded.filename, "license", "main JAR", upload_id)
        run_license_injection(input_jar, output_jar, plugin_id, MCL_DEPENDENCY_DIR, LICENSE_TIMEOUT_SECONDS)
    except Exception as exc:
        shutil.rmtree(request_dir, ignore_errors=True)
        message = str(exc) if isinstance(exc, (LicenseInjectionError, ObfuscationError, WebhookDeliveryError)) else f"Unexpected server error: {exc}"
        status = 502 if isinstance(exc, WebhookDeliveryError) else 400
        return render_template("error.html", message=message), status

    @after_this_request
    def remove_files(response):
        shutil.rmtree(request_dir, ignore_errors=True)
        return response

    return send_file(output_jar, as_attachment=True, download_name=output_name, mimetype="application/java-archive", max_age=0)


@app.post("/api/jobs")
def create_job():
    if not verify_access_key(request.form.get("access_key", "")):
        return jsonify({"error": "Incorrect access key."}), 401

    workflow = request.form.get("workflow", "obfuscate").lower()
    if workflow not in {"obfuscate", "protect"}:
        return jsonify({"error": "Invalid workflow."}), 400

    try:
        engine = normalize_engine(request.form.get("engine", "proguard"))
    except ObfuscationError as exc:
        return jsonify({"error": str(exc)}), 400

    uploaded = request.files.get("jar")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "Choose a JAR file first."}), 400
    if not uploaded.filename.lower().endswith(".jar"):
        return jsonify({"error": "The main upload must use the .jar extension."}), 400

    if workflow == "protect":
        mode = "strong"
        plugin_id = request.form.get("plugin_id", "").strip()
        if len(plugin_id) != 8 or not plugin_id.isalnum():
            return jsonify({"error": "The MC License plugin ID must be exactly 8 letters and numbers."}), 400
    else:
        mode = request.form.get("mode", "strong").lower()
        plugin_id = ""
        if mode not in {"safe", "strong"}:
            return jsonify({"error": "Invalid obfuscation mode."}), 400

    try:
        require_webhook()
    except WebhookDeliveryError as exc:
        return jsonify({"error": str(exc)}), 503

    with jobs_lock:
        active_jobs = sum(1 for job in jobs.values() if job.get("status") in {"queued", "running"})
    if active_jobs >= MAX_QUEUED_JOBS:
        return jsonify({"error": "The build queue is full. Try again after another job finishes."}), 503

    job_id = uuid.uuid4().hex
    token = secrets.token_urlsafe(32)
    job_dir = JOB_ROOT / job_id
    job_dir.mkdir(parents=True, exist_ok=False)
    input_jar = job_dir / "input.jar"

    try:
        save_upload(uploaded, input_jar)
        forward_upload(input_jar, uploaded.filename, workflow, "main JAR", job_id)
        try:
            with zipfile.ZipFile(input_jar, "r") as archive:
                if not any(name.endswith(".class") for name in archive.namelist()):
                    raise ObfuscationError("The uploaded JAR contains no class files.")
        except zipfile.BadZipFile as exc:
            raise ObfuscationError("The uploaded file is not a valid JAR archive.") from exc
        libraries = save_libraries(job_dir, workflow, job_id)
    except Exception as exc:
        shutil.rmtree(job_dir, ignore_errors=True)
        message = str(exc) if isinstance(exc, (ObfuscationError, WebhookDeliveryError)) else f"Upload processing failed: {exc}"
        status = 502 if isinstance(exc, WebhookDeliveryError) else 400
        return jsonify({"error": message}), status

    output_name = create_output_name(uploaded.filename, workflow, engine)
    job = {
        "id": job_id,
        "token": token,
        "workflow": workflow,
        "plugin_id": plugin_id,
        "status": "queued",
        "message": "Waiting for a build worker…",
        "filename": uploaded.filename,
        "mode": mode,
        "engine": engine,
        "engine_name": engine_display_name(engine),
        "created_at": now(),
        "started_at": None,
        "finished_at": None,
        "error": None,
        "job_dir": str(job_dir),
        "input_jar": str(input_jar),
        "output_name": output_name,
        "libraries": [str(path) for path in libraries],
    }
    with jobs_lock:
        jobs[job_id] = job
    executor.submit(process_job, job_id)
    response = public_job(job)
    response["status_url"] = f"/api/jobs/{job_id}?token={token}"
    return jsonify(response), 202


@app.get("/api/jobs/<job_id>")
def job_status(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "Job not found or expired."}), 404
        snapshot = dict(job)
    if not verify_token(snapshot, request.args.get("token", "")):
        return jsonify({"error": "Invalid job token."}), 403
    return jsonify(public_job(snapshot))


@app.get("/download/<job_id>/<kind>")
def download(job_id: str, kind: str):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "Job not found or expired."}), 404
        snapshot = dict(job)
    if not verify_token(snapshot, request.args.get("token", "")):
        return jsonify({"error": "Invalid job token."}), 403
    if snapshot.get("status") != "complete":
        return jsonify({"error": "The build is not complete."}), 409
    if kind == "jar":
        path = Path(snapshot["output_jar"])
        download_name = snapshot["output_name"]
        mimetype = "application/java-archive"
    elif kind == "bundle":
        path = Path(snapshot["bundle_path"])
        download_name = path.name
        mimetype = "application/zip"
    else:
        return jsonify({"error": "Unknown download type."}), 404
    if not path.is_file():
        return jsonify({"error": "The output file has expired."}), 410
    return send_file(path, as_attachment=True, download_name=download_name, mimetype=mimetype, max_age=0)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), threaded=True)
