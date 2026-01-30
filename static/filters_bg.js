// static/filters_bg.js
// TFJS + UNet segmentation model to create background effects stream.
// Supports: blur / image / video / color.
// Fixed: no async inside tidy + prevents async stacking (inFlight).

export async function createBgStream({
  inputStream,
  modelUrl = "/static/tfjs_unet/model.json",

  // pipeline perf
  fps = 20,
  workW = 640,
  workH = 480,
  imgSize = 256,

  // mask smoothing / edges
  tempSmooth = 0.85,
  maskFeatherPx = 6,

  // background mode
  bgMode = "blur", // "blur" | "image" | "video" | "color"
  blurPx = 12,
  bgColor = "#1f1f1f",

  // for bgMode="image" or "video"
  bgSrc = null,    // URL string OR HTMLImageElement/HTMLVideoElement

  // output fps
  outFps = 25,
} = {}) {
  if (!window.tf) {
    await loadScript("https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@4.20.0/dist/tf.min.js");
  }
  const tf = window.tf;

  try { await tf.setBackend("webgl"); } catch {}
  await tf.ready();

  const model = await tf.loadGraphModel(modelUrl);
  const inputName = (model.inputs?.[0]?.name)
    ? model.inputs[0].name.split(":")[0]
    : null;

  // ---- input video ----
  const video = document.createElement("video");
  video.autoplay = true;
  video.playsInline = true;
  video.muted = true;
  video.srcObject = inputStream;
  await video.play();

  // ---- output canvas ----
  const canvas = document.createElement("canvas");
  canvas.width = workW;
  canvas.height = workH;
  const ctx = canvas.getContext("2d", { willReadFrequently: false });

  // ---- inference canvas 256x256 ----
  const small = document.createElement("canvas");
  small.width = imgSize;
  small.height = imgSize;
  const sctx = small.getContext("2d", { willReadFrequently: false });
  const sw = imgSize, sh = imgSize;

  // ---- mask canvases ----
  // 1) small mask canvas (must exist before createImageData)
  const smallMaskCanvas = document.createElement("canvas");
  smallMaskCanvas.width = sw;
  smallMaskCanvas.height = sh;
  const smallMaskCtx = smallMaskCanvas.getContext("2d", { willReadFrequently: true });

  const smallMaskImageData = smallMaskCtx.createImageData(sw, sh);

  // 2) full-size mask canvas
  const maskCanvas = document.createElement("canvas");
  maskCanvas.width = workW;
  maskCanvas.height = workH;
  const mctx = maskCanvas.getContext("2d", { willReadFrequently: true });

  // 3) feather canvas
  const featherCanvas = document.createElement("canvas");
  featherCanvas.width = workW;
  featherCanvas.height = workH;
  const fctx = featherCanvas.getContext("2d");


  // ---- sharp person canvas ----
  const sharpCanvas = document.createElement("canvas");
  sharpCanvas.width = workW;
  sharpCanvas.height = workH;
  const sharpCtx = sharpCanvas.getContext("2d", { willReadFrequently: false });

  // ---- background source element (optional) ----
  let bgEl = await prepareBackgroundElement(bgMode, bgSrc);

  let running = true;
  let lastT = 0;
  let inFlight = false;
  let prevMaskU8 = null;

  function temporalSmoothMask(maskU8) {
    if (!tempSmooth || tempSmooth <= 0) return maskU8;

    if (!prevMaskU8) {
      prevMaskU8 = new Uint8Array(maskU8);
      return prevMaskU8;
    }

    const a = tempSmooth, b = 1 - a;
    for (let i = 0; i < maskU8.length; i++) {
      prevMaskU8[i] = (a * prevMaskU8[i] + b * maskU8[i]) | 0;
    }
    return prevMaskU8;
  }

  function buildSmallMaskImageData(alphaU8) {
    const d = smallMaskImageData.data;
    for (let i = 0, p = 0; i < alphaU8.length; i++, p += 4) {
      d[p + 0] = 255;
      d[p + 1] = 255;
      d[p + 2] = 255;
      d[p + 3] = alphaU8[i];
    }
  }

  function upsampleMaskToFullAndFeather() {
    smallMaskCtx.putImageData(smallMaskImageData, 0, 0);

    mctx.clearRect(0, 0, workW, workH);
    mctx.imageSmoothingEnabled = true;
    mctx.drawImage(smallMaskCanvas, 0, 0, workW, workH);

    if (maskFeatherPx && maskFeatherPx > 0) {
      fctx.clearRect(0, 0, workW, workH);
      fctx.filter = `blur(${maskFeatherPx}px)`;
      fctx.drawImage(maskCanvas, 0, 0, workW, workH);
      fctx.filter = "none";

      mctx.clearRect(0, 0, workW, workH);
      mctx.drawImage(featherCanvas, 0, 0, workW, workH);
    }
  }

  async function inferMaskU8() {
    sctx.drawImage(video, 0, 0, sw, sh);

    const alphaTensor = tf.tidy(() => {
      const img = tf.browser.fromPixels(small).toFloat().div(255);
      const batched = img.expandDims(0);

      let out;
      try { out = model.execute(batched); }
      catch (e) {
        if (!inputName) throw e;
        out = model.execute({ [inputName]: batched });
      }

      const t = Array.isArray(out) ? out[0] : out;
      const logits = t.squeeze();
      const prob = tf.sigmoid(tf.clipByValue(logits, -30, 30));
      return prob.mul(255).toInt();
    });

    const data = await alphaTensor.data();
    alphaTensor.dispose();
    return (data instanceof Uint8Array) ? data : Uint8Array.from(data);
  }

  function drawBackgroundLayer() {
    // draw full-frame background into ctx
    if (bgMode === "blur") {
      ctx.filter = `blur(${blurPx}px)`;
      ctx.drawImage(video, 0, 0, workW, workH);
      ctx.filter = "none";
      return;
    }

    if (bgMode === "color") {
      ctx.fillStyle = bgColor;
      ctx.fillRect(0, 0, workW, workH);
      return;
    }

    if (bgMode === "image" || bgMode === "video") {
      if (bgEl) {
        // cover-style draw (no stretching)
        drawCover(ctx, bgEl, workW, workH);
      } else {
        // fallback
        ctx.fillStyle = "#000";
        ctx.fillRect(0, 0, workW, workH);
      }
      return;
    }

    // fallback
    ctx.drawImage(video, 0, 0, workW, workH);
  }

  async function step(ts) {
    if (!running) return;
    requestAnimationFrame(step);

    if (ts - lastT < (1000 / fps)) return;
    if (inFlight) return;
    inFlight = true;

    try {
      lastT = ts;

      const rawMaskU8 = await inferMaskU8();
      const maskU8 = temporalSmoothMask(rawMaskU8);

      buildSmallMaskImageData(maskU8);
      upsampleMaskToFullAndFeather();

      // 1) background
      ctx.clearRect(0, 0, workW, workH);
      drawBackgroundLayer();

      // 2) sharp person
      sharpCtx.clearRect(0, 0, workW, workH);
      sharpCtx.drawImage(video, 0, 0, workW, workH);

      // 3) apply mask
      sharpCtx.save();
      sharpCtx.globalCompositeOperation = "destination-in";
      sharpCtx.drawImage(maskCanvas, 0, 0, workW, workH);
      sharpCtx.restore();

      // 4) composite
      ctx.drawImage(sharpCanvas, 0, 0, workW, workH);
    } catch (err) {
      console.error("[FILTER] bg pipeline error:", err);
    } finally {
      inFlight = false;
    }
  }

  requestAnimationFrame(step);

  // output stream with original audio
  const outStream = canvas.captureStream(outFps);
  const existing = new Set(outStream.getAudioTracks().map(t => t.id));
  inputStream.getAudioTracks().forEach(t => {
    if (!existing.has(t.id)) outStream.addTrack(t);
  });


  return {
    stream: outStream,

    async setBgMode(newMode) {
      bgMode = newMode;
      bgEl = await prepareBackgroundElement(bgMode, bgSrc);
    },

    setBlur(px) { blurPx = px; },
    setColor(c) { bgColor = c; },

    async setBgSrc(src) {
      bgSrc = src;
      bgEl = await prepareBackgroundElement(bgMode, bgSrc);
    },

    stop() {
      running = false;
      try { video.pause(); } catch {}
      try { video.srcObject = null; } catch {}
      try { model.dispose(); } catch {}
      prevMaskU8 = null;

      // stop bg video if created
      try {
        if (bgEl && bgEl.tagName === "VIDEO") {
          bgEl.pause();
          bgEl.src = "";
        }
      } catch {}
    },
    debug: {
      inputName,
      modelInputs: model.inputs?.map(x => ({ name: x.name, shape: x.shape })),
      modelOutputs: model.outputs?.map(x => ({ name: x.name, shape: x.shape })),
    },
    _bgEl: bgEl,
  };
}

async function prepareBackgroundElement(bgMode, bgSrc) {
  if (!bgSrc) return null;

  // If already an element
  if (bgSrc instanceof HTMLImageElement || bgSrc instanceof HTMLVideoElement) {
    if (bgSrc instanceof HTMLVideoElement && bgMode === "video") {
      if (bgSrc.readyState < 2) {
        await bgSrc.play().catch(() => {});
      }
    }
    return bgSrc;
  }

  // If URL string
  if (typeof bgSrc === "string") {
    if (bgMode === "image") {
      const img = new Image();
      img.crossOrigin = "anonymous";
      img.src = bgSrc;
      await img.decode().catch(() => {});
      return img;
    }

    if (bgMode === "video") {
      const v = document.createElement("video");
      v.crossOrigin = "anonymous";
      v.loop = true;
      v.muted = true;
      v.playsInline = true;
      v.autoplay = true;
      v.src = bgSrc;

      await new Promise((res) => {
        v.onloadeddata = () => res();
        v.onerror = () => res(); // fail-soft
      });

      await v.play().catch(() => {});
      return v;
    }
  }

  return null;
}

// Draw source (image/video) as "cover" (like CSS background-size: cover)
function drawCover(ctx, el, W, H) {
  const vw = el.videoWidth || el.naturalWidth || W;
  const vh = el.videoHeight || el.naturalHeight || H;
  if (!vw || !vh) {
    ctx.drawImage(el, 0, 0, W, H);
    return;
  }

  const s = Math.max(W / vw, H / vh);
  const dw = vw * s;
  const dh = vh * s;
  const dx = (W - dw) / 2;
  const dy = (H - dh) / 2;
  ctx.drawImage(el, dx, dy, dw, dh);
}

function loadScript(src) {
  return new Promise((res, rej) => {
    const s = document.createElement("script");
    s.src = src;
    s.onload = res;
    s.onerror = rej;
    document.head.appendChild(s);
  });
}
