'use strict';

document.addEventListener('DOMContentLoaded', () => {
  const dropzone = document.querySelector('#dropzone');
  const fileInput = document.querySelector('#plugin-file');
  const fileLabel = document.querySelector('#file-label');

  if (dropzone && fileInput && fileLabel) {
    const showFile = () => {
      const file = fileInput.files?.[0];
      if (!file) return;
      fileLabel.textContent = `${file.name} · ${(file.size / 1024 / 1024).toFixed(2)} MB`;
    };

    fileInput.addEventListener('change', showFile);
    for (const eventName of ['dragenter', 'dragover']) {
      dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.add('dragging');
      });
    }
    for (const eventName of ['dragleave', 'drop']) {
      dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.remove('dragging');
      });
    }
    dropzone.addEventListener('drop', (event) => {
      const file = event.dataTransfer?.files?.[0];
      if (!file) return;
      const transfer = new DataTransfer();
      transfer.items.add(file);
      fileInput.files = transfer.files;
      showFile();
    });
  }

  document.querySelectorAll('[data-tabs]').forEach((tabs) => {
    const buttons = [...tabs.querySelectorAll('[data-tab]')];
    const panels = [...tabs.querySelectorAll('[data-panel]')];

    buttons.forEach((button) => {
      button.addEventListener('click', () => {
        const selected = button.dataset.tab;
        buttons.forEach((item) => item.classList.toggle('active', item === button));
        panels.forEach((panel) => panel.classList.toggle('active', panel.dataset.panel === selected));
      });
    });
  });
});
