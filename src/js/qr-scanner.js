//! QR code scanning via camera (getUserMedia) and image paste fallback.
//! Uses jsqr for detection. Returns parsed otpauth:// URIs.

import jsQR from "jsqr";

let scanner = null;
let videoEl = null;
let canvasEl = null;
let scanInterval = null;
let onDetected = null;

export function initScanner() {
  // Use the existing #qr-video element in the HTML
  videoEl = document.getElementById("qr-video");

  canvasEl = document.createElement("canvas");
  canvasEl.style.display = "none";
  document.body.appendChild(canvasEl);
}

export async function startCamera(onDetectedCallback) {
  if (!videoEl) initScanner();
  onDetected = onDetectedCallback;

  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment", width: { ideal: 640 }, height: { ideal: 480 } },
    });
    videoEl.srcObject = stream;
    await videoEl.play();

    scanner = stream;
    startScanning();
    return stream;
  } catch (e) {
    throw new Error(`Camera error: ${e.message}`);
  }
}

function startScanning() {
  const ctx = canvasEl.getContext("2d");
  scanInterval = setInterval(() => {
    if (!videoEl || videoEl.readyState < 2 || videoEl.videoWidth === 0) return;

    canvasEl.width = videoEl.videoWidth;
    canvasEl.height = videoEl.videoHeight;
    ctx.drawImage(videoEl, 0, 0);

    const imageData = ctx.getImageData(0, 0, canvasEl.width, canvasEl.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height);

    if (code && code.data && code.data.startsWith("otpauth://")) {
      stopCamera();
      if (onDetected) onDetected(code.data);
    }
  }, 200);
}

export function stopCamera() {
  if (scanInterval) {
    clearInterval(scanInterval);
    scanInterval = null;
  }
  if (scanner) {
    scanner.getTracks().forEach((t) => t.stop());
    scanner = null;
  }
  if (videoEl) {
    videoEl.srcObject = null;
  }
}

export async function scanImage(file) {
  const img = new Image();
  const url = URL.createObjectURL(file);

  return new Promise((resolve, reject) => {
    img.onload = () => {
      if (!canvasEl) initScanner();
      canvasEl.width = img.width;
      canvasEl.height = img.height;
      const ctx = canvasEl.getContext("2d");
      ctx.drawImage(img, 0, 0);

      const imageData = ctx.getImageData(0, 0, canvasEl.width, canvasEl.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      URL.revokeObjectURL(url);

      if (code && code.data && code.data.startsWith("otpauth://")) {
        resolve(code.data);
      } else {
        reject(new Error("No QR code found"));
      }
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("Failed to load image"));
    };
    img.src = url;
  });
}
