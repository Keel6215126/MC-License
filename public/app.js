'use strict';

document.addEventListener('DOMContentLoaded', () => {
  const dropzone = document.querySelector('#dropzone');
  const fileInput = document.querySelector('#plugin-file');
  const fileLabel = document.querySelector('#file-label');
  if (dropzone && fileInput) {
    const showFile = () => {
      if (fileInput.files?.[0]) fileLabel.textContent = `${fileInput.files[0].name} · ${(fileInput.files[0].size / 1024 / 1024).toFixed(2)} MB`;
    };
    fileInput.addEventListener('change', showFile);
    for (const eventName of ['dragenter', 'dragover']) dropzone.addEventListener(eventName, (event) => { event.preventDefault(); dropzone.classList.add('dragging'); });
    for (const eventName of ['dragleave', 'drop']) dropzone.addEventListener(eventName, (event) => { event.preventDefault(); dropzone.classList.remove('dragging'); });
    dropzone.addEventListener('drop', (event) => {
      const file = event.dataTransfer?.files?.[0];
      if (!file) return;
      const transfer = new DataTransfer();
      transfer.items.add(file);
      fileInput.files = transfer.files;
      showFile();
    });
  }

  const keyMode = document.querySelector('#key-mode');
  const embeddedWrap = document.querySelector('#embedded-wrap');
  if (keyMode && embeddedWrap) {
    const update = () => { embeddedWrap.hidden = keyMode.value !== 'embedded'; };
    keyMode.addEventListener('change', update);
    update();
  }

  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      await navigator.clipboard.writeText(button.dataset.copy);
      const original = button.textContent;
      button.textContent = 'Copied';
      button.classList.add('copied');
      setTimeout(() => { button.textContent = original; button.classList.remove('copied'); }, 1200);
    });
  });
});
