// ---------- Crypto: DH + AES (per-peer) ----------
const PRIME = (2n ** 2048n) - 159n;
const GENERATOR = 2n;

function modPow(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    exponent >>= 1n;
    base = (base * base) % modulus;
  }
  return result;
}
function sha256(s) { return crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)); }
async function deriveKey(sharedSecretBigInt) {
  const digest = await sha256(sharedSecretBigInt.toString());
  const keyBytes = new Uint8Array(digest).slice(0, 16); // AES-128
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["encrypt","decrypt"]);
}
async function aesEncrypt(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const data = new TextEncoder().encode(text);
  const padLen = 16 - (data.length % 16);
  const padded = new Uint8Array([...data, ...new Array(padLen).fill(padLen)]);
  const ct = await crypto.subtle.encrypt({ name:"AES-CBC", iv }, key, padded);
  const combined = new Uint8Array([...iv, ...new Uint8Array(ct)]);
  return btoa(String.fromCharCode(...combined));
}
async function aesDecrypt(key, b64) {
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const iv = bytes.slice(0, 16);
  const ct = bytes.slice(16);
  const pt = await crypto.subtle.decrypt({ name:"AES-CBC", iv }, key, ct);
  const u8 = new Uint8Array(pt);
  const pad = u8[u8.length - 1];
  return new TextDecoder().decode(u8.slice(0, u8.length - pad));
}

// ---------- DOM ----------
const localVideo  = document.getElementById("localVideo");
const remotesWrap = document.getElementById("remotes") || document.getElementById("remoteVideo")?.parentElement;
const localScreen  = document.getElementById("localScreen");
const screensWrap  = document.getElementById("screens");

// Chat DOM
const chatLog   = document.getElementById("chatLog");
const chatForm  = document.getElementById("chatForm");
const chatInput = document.getElementById("chatInput");

const audioContexts = {};
const audioAnalysers = {};
const audioVolumes = {};

// Device selects
const micSelect = document.getElementById("micSelect");
const camSelect = document.getElementById("camSelect");
const spkSelect = document.getElementById("spkSelect");

function logFilter(...a){ console.log("%c[FILTER]", "color:#7cf;font-weight:700", ...a); }
function logModel(...a){ console.log("%c[MODEL]", "color:#fc7;font-weight:700", ...a); }
function logErr(tag, e){ console.error(`%c[${tag}]`, "color:#f77;font-weight:900", e); }


function appendChatLine(text, opts = {}) {
  if (!chatLog) return;
  const { from, self, system } = opts;

  const line = document.createElement("div");
  line.className = "chat-line";
  if (system) line.classList.add("system");
  else if (self) line.classList.add("self");
  else line.classList.add("other");

  if (system) {
    line.textContent = text;
  } else {
    const fromSpan = document.createElement("span");
    fromSpan.className = "from";
    fromSpan.textContent = from || "??";

    const textSpan = document.createElement("span");
    textSpan.textContent = text;

    line.appendChild(fromSpan);
    line.appendChild(textSpan);
  }

  chatLog.appendChild(line);
  chatLog.scrollTop = chatLog.scrollHeight;
}

function updateRemoteLayout() {
  const wrap = remotesWrap;
  if (!wrap) return;

  // Count only actual tiles (divs that contain a <video>)
  const tiles = Array.from(wrap.children).filter(el => el.querySelector("video"));
  const count = tiles.length;

  wrap.classList.remove("layout-1", "layout-4", "layout-9", "layout-many");

  if (count <= 1) {
    wrap.classList.add("layout-1");
  } else if (count <= 4) {
    wrap.classList.add("layout-4");
  } else if (count <= 9) {
    wrap.classList.add("layout-9");
  } else {
    wrap.classList.add("layout-many");
  }
}

function attachAudioAnalyzer(peer, stream) {
  try {
    if (!stream) return;
    const audioTracks = stream.getAudioTracks();
    if (!audioTracks.length) return;

    if (audioAnalysers[peer]) return;

    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const analyser = ctx.createAnalyser();
    analyser.fftSize = 512;

    const srcStream = new MediaStream([audioTracks[0]]);
    const source = ctx.createMediaStreamSource(srcStream);
    source.connect(analyser);

    audioContexts[peer]  = ctx;
    audioAnalysers[peer] = analyser;

    console.log("[VAD] Analyzer attached for", peer);
  } catch (err) {
    console.warn("[VAD] attachAudioAnalyzer error:", err);
  }
}

// ----------- DEVICE ENUMERATION -----------
async function refreshDeviceLists() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
    console.warn("[DEVICES] enumerateDevices not supported");
    return;
  }

  let devices;
  try {
    devices = await navigator.mediaDevices.enumerateDevices();
  } catch (err) {
    console.warn("[DEVICES] enumerateDevices failed:", err);
    return;
  }

  const mics = devices.filter(d => d.kind === "audioinput");
  const cams = devices.filter(d => d.kind === "videoinput");
  const spks = devices.filter(d => d.kind === "audiooutput");

  // Mic list
  if (micSelect) {
    const current = micSelect.value;
    micSelect.innerHTML = "";
    const defOpt = document.createElement("option");
    defOpt.value = "";
    defOpt.textContent = "Default microphone";
    micSelect.appendChild(defOpt);

    mics.forEach(d => {
      const opt = document.createElement("option");
      opt.value = d.deviceId;
      opt.textContent = d.label || `Microphone ${micSelect.length}`;
      micSelect.appendChild(opt);
    });

    if (current && Array.from(micSelect.options).some(o => o.value === current)) {
      micSelect.value = current;
    }
  }

  // Camera list
  if (camSelect) {
    const current = camSelect.value;
    camSelect.innerHTML = "";
    const defOpt = document.createElement("option");
    defOpt.value = "";
    defOpt.textContent = "Default camera";
    camSelect.appendChild(defOpt);

    cams.forEach(d => {
      const opt = document.createElement("option");
      opt.value = d.deviceId;
      opt.textContent = d.label || `Camera ${camSelect.length}`;
      camSelect.appendChild(opt);
    });

    if (current && Array.from(camSelect.options).some(o => o.value === current)) {
      camSelect.value = current;
    }
  }

  // Speakers list
  if (spkSelect) {
    const current = spkSelect.value;
    spkSelect.innerHTML = "";
    const defOpt = document.createElement("option");
    defOpt.value = "";
    defOpt.textContent = "Default speakers";
    spkSelect.appendChild(defOpt);

    spks.forEach(d => {
      const opt = document.createElement("option");
      opt.value = d.deviceId;
      opt.textContent = d.label || `Speakers ${spkSelect.length}`;
      spkSelect.appendChild(opt);
    });

    if (current && Array.from(spkSelect.options).some(o => o.value === current)) {
      spkSelect.value = current;
    }
  }
}

if (navigator.mediaDevices && navigator.mediaDevices.addEventListener) {
  navigator.mediaDevices.addEventListener("devicechange", () => {
    refreshDeviceLists().catch(()=>{});
  });
}


if (localVideo) localVideo.muted = true;
if (localScreen) localScreen.muted = true;


// Utility: create/get a remote <video> for a user
function getRemoteVideoEl(peer) {
  let el = document.getElementById(`video-${peer}`);
  if (!el) {
    el = document.createElement("video");
    el.id = `video-${peer}`;
    el.autoplay = true;
    el.playsInline = true;
    el.style.background = "#000";
    el.style.border = "1px solid #333";
    el.style.borderRadius = "10px";

    const box = document.createElement("div");
    const pill = document.createElement("div");
    pill.textContent = peer;
    pill.className = "pill";
    box.appendChild(pill);
    box.appendChild(el);
    (remotesWrap || document.body).appendChild(box);

    updateRemoteLayout();
  }
  return el;
}


// ---------- WebSocket (STAR) ----------
/*
  Server should do:
  - Broadcast presence: {type:'peer_list', users:[...]} on join
  - Notify: {type:'peer_joined', user:'...'}, {type:'peer_left', user:'...'}
  - Relay signaling: messages with {to, from, type:'signal', data:{...}} (opaque)
  - Relay host controls: {type:'host_mute', to:'*' | username}, {type:'host_kick', to:username}
*/
const socket = new WebSocket(`wss://${location.hostname}:8000?room=${encodeURIComponent(roomId)}&user=${encodeURIComponent(username)}`);
const sendPlain = (obj) => socket.send(JSON.stringify({ ...obj, from: username }));

// ---------- ICE/STUN/TURN ----------

let ICE_SERVERS = null;

async function getIceServers(roomId) {
  const r = await fetch(`/api/ice?room=${encodeURIComponent(roomId)}`, { credentials: "include" });
  const txt = await r.text(); // read body even on error
  if (!r.ok) throw new Error(`ICE fetch failed: ${r.status} ${txt}`);
  return JSON.parse(txt).iceServers;
}


async function initIceServers() {
  if (ICE_SERVERS) return ICE_SERVERS;
  ICE_SERVERS = await getIceServers(roomId);
  return ICE_SERVERS;
}

// ---------- Local media ----------
let localStream, videoSender, originalVideoTrack, blackStream, blackTrack;

let filteredStream = null;
let filteredVideoTrack = null;
let filterStopFn = null;

(async function initLocalMedia() {
  const autoCam = !!(window.prefs && window.prefs.autoCam);
  const autoMic = !!(window.prefs && window.prefs.autoMic);

  logFilter("prefs:", window.prefs);
  logFilter("autoCam:", autoCam, "autoMic:", autoMic);
  logFilter("bg_mode:", window.prefs?.bg_mode, "blur_strength:", window.prefs?.blur_strength);

  // Always ask for audio, then apply pref by disabling
  const stream = await navigator.mediaDevices.getUserMedia({
    video: true,
    audio: true,
  });

  localStream = stream;
  originalVideoTrack = localStream.getVideoTracks()[0] || null;

  // Mic pref
  const aTracks = localStream.getAudioTracks();
  if (aTracks.length) {
    aTracks.forEach(t => (t.enabled = autoMic));
    isMuted = !autoMic;
  } else {
    isMuted = true;
  }

  // Prepare black frame (camera-off)
  const c = document.createElement("canvas");
  c.width = 640; c.height = 480;
  const ctx = c.getContext("2d");
  ctx.fillStyle = "black";
  ctx.fillRect(0, 0, c.width, c.height);
  blackStream = c.captureStream(5);
  blackTrack = blackStream.getVideoTracks()[0];

  // Camera pref
  isVideoOff = !autoCam;

  // Default preview
  if (localVideo) {
    if (isVideoOff) {
      const preview = new MediaStream([blackTrack]);
      localStream.getAudioTracks().forEach(a => preview.addTrack(a));
      localVideo.srcObject = preview;
    } else {
      localVideo.srcObject = localStream;
    }
    try { await localVideo.play(); } catch {}
  }

  logFilter("cameraOff?", isVideoOff, "bg_mode?", window.prefs?.bg_mode);

  if (!isVideoOff && window.prefs?.bg_mode && window.prefs.bg_mode !== "none") {
    if (!window.FilterEngine?.createBgStream) {
      console.warn("[FILTER] FilterEngine not loaded");
    } else {
      try { filterStopFn && filterStopFn(); } catch {}

      let bgMode = window.prefs?.bg_mode || "none";
      const blurPx = Number(window.prefs?.blur_strength || 12);
      const bgSrc  = window.prefs?.bg_src || null;
      const bgColor = window.prefs?.bg_color || "#1f1f1f";

      if (bgMode === "image_upload" || bgMode === "image_url") bgMode = "image";

      const engine = await window.FilterEngine.createBgStream({
        inputStream: localStream,
        modelUrl: "/static/tfjs_unet/model.json",
        fps: 20,
        workW: 640,
        workH: 480,
        imgSize: 256,
        bgMode,
        blurPx,
        bgSrc,
        bgColor,
      });


      filteredStream = engine.stream;
      filteredVideoTrack = filteredStream.getVideoTracks()[0] || null;
      filterStopFn = engine.stop || null;

      for (const u in peers) {
        const s = peers[u].pc.getSenders().find(x => x.track?.kind === "video");
        if (s && filteredVideoTrack) {
          try { await s.replaceTrack(filteredVideoTrack); } catch(e) {}
        }
      }

      // local preview
      if (localVideo) {
        localVideo.srcObject = filteredStream;
        try { await localVideo.play(); } catch {}
      }
    }
  }

  updateButtonsUI();
  refreshDeviceLists().catch(()=>{});

  console.log("[MEDIA] Local ready");
})();

function getCurrentVideoTrack() {
  if (!isVideoOff && filteredVideoTrack) return filteredVideoTrack;

  if (isVideoOff && blackTrack) return blackTrack;

  return originalVideoTrack;
}



// ---------- Per-peer state ----------
/*
  peers[user] = {
    pc,
    dhPrivate, dhPublic, sharedKey,
    sendQueue: [],
    incomingCandidates: [],
    readyFromPeer: false,
    makingOffer: false,
    videoEl
  }
*/
const peers = {};
const participants = new Set([username]);

function ensurePeer(user) {
  if (user === username) return null;
  if (peers[user]) return peers[user];

  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS || [] });

  watchPC(user, pc);

  pc.addTransceiver("video", { direction: "sendrecv" });
  pc.addTransceiver("audio", { direction: "sendrecv" });

  pc.onnegotiationneeded = async () => {
    const p = peers[user];
    if (!p) return;
    if (p.makingOffer) return;
    try {
      p.makingOffer = true;
      await waitLocalMedia();
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await sendSecure(user, { type: "offer", offer });
      console.log(`[RTC] Renegotiation offer sent to ${user}`);
    } catch (e) {
      console.warn("[RTC] onnegotiationneeded failed:", e);
    } finally {
      p.makingOffer = false;
    }
  };

  // Add our tracks (AUDIO from localStream, VIDEO from current mode)
  const addMyTracks = () => {
    if (!localStream) return false;

    localStream.getAudioTracks().forEach(t => {
      pc.addTrack(t, localStream);
    });

    const v = getCurrentVideoTrack();
    if (v) {
      const sender = pc.addTrack(v, localStream);
      videoSender = sender;
    }

    return true;
  };

  if (!addMyTracks()) {
    const int = setInterval(() => {
      if (addMyTracks()) clearInterval(int);
    }, 200);
  }

  if (screenStream && screenTrack) {
    const sender = pc.addTrack(screenTrack, screenStream);
    if (!screenSenders[user]) screenSenders[user] = [];
    screenSenders[user].push(sender);
  }

  const videoEl = getRemoteVideoEl(user);

  pc.ontrack = async (e) => {
    const track  = e.track;
    const stream = e.streams && e.streams[0] ? e.streams[0] : null;
    const peerState = peers[user];

    if (!peerState) return;

    if (track.kind === "video") {
      let isScreen = false;

      if (stream) {

        if (!peerState.cameraStreamId) {
          peerState.cameraStreamId = stream.id;
          isScreen = false;
        } else if (stream.id === peerState.cameraStreamId) {
          isScreen = false;
        } else {
          // Any other video stream = screen share
          peerState.screenStreamId = stream.id;
          isScreen = true;
        }
      }

      if (!isScreen) {
        // -------- CAMERA VIDEO --------
        const videoEl = peerState.videoEl || getRemoteVideoEl(user);

        if (stream) {
          if (videoEl.srcObject !== stream) {
            videoEl.srcObject = stream;
          } else if (!videoEl.srcObject.getTracks().includes(track)) {
            videoEl.srcObject.addTrack(track);
          }
        } else {
          if (!videoEl.srcObject) videoEl.srcObject = new MediaStream();
          if (!videoEl.srcObject.getTracks().includes(track)) {
            videoEl.srcObject.addTrack(track);
          }
        }

        try { await videoEl.play(); } catch {}
        console.log(`[RTC] Remote CAMERA stream bound: ${user}`);

      } else {
        // -------- SCREEN SHARE VIDEO --------
        let el = document.getElementById(`screen-${user}`);
        if (!el) {
          el = document.createElement("video");
          el.id = `screen-${user}`;
          el.autoplay = true;
          el.playsInline = true;
          el.style.width = "640px";
          el.style.maxWidth = "100%";
          el.style.background = "#000";
          el.style.border = "2px solid #0af";
          el.style.borderRadius = "10px";

          const box = document.createElement("div");
          const pill = document.createElement("div");
          pill.textContent = `${user} (screen)`;
          pill.className = "pill";
          box.appendChild(pill);
          box.appendChild(el);
          (screensWrap || remotesWrap || document.body).appendChild(box);
        }

        if (stream) {
          if (el.srcObject !== stream) {
            el.srcObject = stream;
          } else if (!el.srcObject.getTracks().includes(track)) {
            el.srcObject.addTrack(track);
          }
        } else {
          if (!el.srcObject) el.srcObject = new MediaStream();
          if (!el.srcObject.getTracks().includes(track)) {
            el.srcObject.addTrack(track);
          }
        }

        try { await el.play(); } catch {}

        // ---- ROBUST CLEANUP WHEN REMOTE STOPS SHARING ----
        const cleanupScreenTile = () => {
          console.log(`[SCREEN] Remote screen from ${user} ended/inactive`);
          const box = el.parentElement;
          if (box) box.remove();
          if (peerState.screenStreamId === (stream && stream.id)) {
            peerState.screenStreamId = null;
          }
        };

        // 1) Track ends (most browsers)
        track.addEventListener("ended", cleanupScreenTile);

        // 2) Stream goes inactive (all tracks ended)
        if (stream) {
          stream.addEventListener("inactive", cleanupScreenTile);
        }

        console.log(`[RTC] Remote SCREEN stream bound: ${user}`);
      }

    } else if (track.kind === "audio") {
      // -------- AUDIO: attach to camera tile --------
      const videoEl = peerState.videoEl || getRemoteVideoEl(user);
      if (!videoEl.srcObject) videoEl.srcObject = new MediaStream();
      if (!videoEl.srcObject.getAudioTracks().includes(track)) {
        videoEl.srcObject.addTrack(track);
      }
      try { await videoEl.play(); } catch {}
      console.log(`[RTC] Remote audio track added: ${user}`);

      // 🔊 NEW: hook this peer into active speaker detection
      const analyseStream = stream || videoEl.srcObject;
      attachAudioAnalyzer(user, analyseStream);
    }
  };




  pc.onicecandidate = (e) => {
    if (e.candidate) sendSecure(user, { type: "candidate", candidate: e.candidate });
  };

  peers[user] = {
    pc,
    dhPrivate: null,
    dhPublic: null,
    sharedKey: null,
    sendQueue: [],
    incomingCandidates: [],
    readyFromPeer: false,
    makingOffer: false,
    videoEl,
    // NEW: track which remote stream is camera vs screen
    cameraStreamId: null,
    screenStreamId: null,
  };


  return peers[user];
}

function detectActiveSpeakers() {
  const THRESH = 0.08; // tweak if too sensitive / not enough

  let loudestPeer = null;
  let loudestValue = 0;

  for (const peer in audioAnalysers) {
    const analyser = audioAnalysers[peer];
    const data = new Uint8Array(analyser.frequencyBinCount);
    analyser.getByteFrequencyData(data);

    // RMS of spectrum
    let sum = 0;
    for (let i = 0; i < data.length; i++) {
      sum += data[i] * data[i];
    }
    const rms = Math.sqrt(sum / data.length) / 255;
    audioVolumes[peer] = rms;

    if (rms > THRESH && rms > loudestValue) {
      loudestValue = rms;
      loudestPeer = peer;
    }
  }

  // Clear all highlights
  const boxes = document.querySelectorAll("#remotes > div");
  boxes.forEach(b => b.classList.remove("active-speaker"));

  // Highlight loudest
  if (loudestPeer) {
    const vid = document.getElementById(`video-${loudestPeer}`);
    if (vid && vid.parentElement) {
      vid.parentElement.classList.add("active-speaker");
    }
  }

  requestAnimationFrame(detectActiveSpeakers);
}

requestAnimationFrame(detectActiveSpeakers);


// ---------- Per-peer crypto/send helpers ----------
function bothReady(user) {
  const p = peers[user];
  return p && p.sharedKey && p.readyFromPeer;
}

async function flushSendQueue(user) {
  const p = peers[user];
  if (!p || !bothReady(user) || p.sendQueue.length === 0) return;
  const items = p.sendQueue.splice(0, p.sendQueue.length);
  for (const obj of items) await sendSecure(user, obj);
}

async function sendSecure(user, obj) {
  const p = peers[user];
  if (!p || !p.sharedKey) { if (p) p.sendQueue.push(obj); return; }
  const enc = await aesEncrypt(p.sharedKey, JSON.stringify(obj));
  socket.send(JSON.stringify({ type: "signal", to: user, from: username, data: { type: "encrypted", b64: enc } }));
}

function sendPlainSignal(user, payload) {
  socket.send(JSON.stringify({ type: "signal", to: user, from: username, data: payload }));
}

// ---------- Offer/Answer/Candidate per peer ----------
async function handleSignalFrom(user, payload) {
  const p = ensurePeer(user);
  const pc = p.pc;

  if (payload.type === "encrypted") {
    if (!p.sharedKey) { console.warn(`[SEC] Encrypted before key from ${user}`); return; }
    let data;
    try { data = JSON.parse(await aesDecrypt(p.sharedKey, payload.b64)); }
    catch (e) { console.error("[SEC] Decrypt failed:", e); return; }
    await handleDecrypted(user, data);
    return;
  }

  // Unencrypted control (DH, READY)
  if (payload.type === "dh_public") {
    if (!p.dhPrivate) {
      const privBytes = crypto.getRandomValues(new Uint8Array(32));
      p.dhPrivate = BigInt("0x" + Array.from(privBytes).map(b => b.toString(16).padStart(2,"0")).join(""));
      p.dhPublic  = modPow(GENERATOR, p.dhPrivate, PRIME);
    }
    const peerPub = BigInt(payload.value);
    const sharedSecret = modPow(peerPub, p.dhPrivate, PRIME);
    p.sharedKey = await deriveKey(sharedSecret);
    // respond with our pub if we haven't sent one yet
    if (!payload.seen_us) {
      sendPlainSignal(user, { type: "dh_public", value: p.dhPublic.toString(), seen_us: true });
    }
    // announce ready
    sendPlainSignal(user, { type: "ready" });
    await flushSendQueue(user);
    return;
  }

  if (payload.type === "ready") {
    p.readyFromPeer = true;
    // Initiator selection to prevent glare
    const iStart = username < user;
    if (iStart && !p.makingOffer) {
      p.makingOffer = true;
      await waitLocalMedia();
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await sendSecure(user, { type: "offer", offer });
    }
    await flushSendQueue(user);
    return;
  }

  if (payload.type === "intro") {
    // Host asks us to connect to 'other'
    const other = payload.other;
    if (other && other !== username) startPeerHandshake(other);
    return;
  }
}

async function handleDecrypted(user, m) {
  const p = peers[user];
  const pc = p.pc;

  if (m.type === "host_payload") {
    // We just became host and were given the sensitive values
    window.roomId  = m.roomId;
    window.roomKey = m.roomKey;
    window.joinLink = m.joinLink;
    hydrateHostPanel(); // fill the footer inputs now visible
    return;
  }

  if (m.type === "offer") {
    await waitLocalMedia();

    // ---- GLARE GUARD ----
    if (pc.signalingState === "have-local-offer") {
      console.warn("[RTC] Glare detected: already have-local-offer, ignoring remote offer from", user);
      return;  // ignore this offer to avoid SSL role error
    }

    try {
      await pc.setRemoteDescription(m.offer);
    } catch (e) {
      console.warn("[RTC] setRemoteDescription(offer) failed:", e);
      return;
    }

    await flushIncomingCandidates(user);

    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await sendSecure(user, { type: "answer", answer });
  } else if (m.type === "answer") {
    try {
      await pc.setRemoteDescription(m.answer);
    } catch (e) {
      console.warn("[RTC] setRemoteDescription(answer) failed:", e);
      return;
    }
    await flushIncomingCandidates(user);
  } else if (m.type === "candidate") {
    if (!m.candidate) return;
    if (!pc.remoteDescription) {
      p.incomingCandidates.push(m.candidate);
    } else {
      try { await pc.addIceCandidate(m.candidate); } catch (e) { console.warn("[ICE] add failed:", e); }
    }
  } else if (m.type === "bye") {
    closePeer(user);
  }
}

async function flushIncomingCandidates(user) {
  const p = peers[user];
  if (!p) return;
  const pc = p.pc;
  if (!pc.remoteDescription) return;
  for (const c of p.incomingCandidates.splice(0)) {
    try { await pc.addIceCandidate(c); } catch(e) { console.warn("[ICE] add failed:", e); }
  }
}

function closePeer(user) {
  const p = peers[user];
  if (!p) return;
  try { p.pc.getSenders().forEach(s => { try { p.pc.removeTrack(s); } catch(e){} }); } catch(e){}
  try { p.pc.close(); } catch(e){}

  // Remove camera video box
  if (p.videoEl && p.videoEl.parentElement) p.videoEl.parentElement.remove();

  // Remove screen video box
  const screenEl = document.getElementById(`screen-${user}`);
  if (screenEl && screenEl.parentElement) screenEl.parentElement.remove();

  delete peers[user];
  participants.delete(user);
  screenSenders[user] = [];   // clear per-peer screen senders
  refreshKickList();

  // 🔁 update layout whenever we remove a tile
  updateRemoteLayout();
}


function setHostButtonsEnabled(enabled) {
  ["hostMuteAll","hostKick","copyLink","copyRoom","copyKey"].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.disabled = !enabled; el.setAttribute("aria-disabled", String(!enabled)); }
  });
}
function setHostUI(isHostNow) {
  window.isHost = !!isHostNow;
  document.body.classList.toggle('is-host', window.isHost);
  setHostButtonsEnabled(window.isHost);
  ensureKickSelectExists(); refreshKickList();
  if (window.isHost) hydrateHostPanel();
}


// read values already in the DOM (owner load) into globals
function cacheHostFieldsFromDOM() {
  const jl = document.getElementById("joinLink")?.value || "";
  const rk = document.getElementById("roomKeyField")?.value || "";
  const rid = document.getElementById("roomIdField")?.value || "";
  if (jl) window.joinLink = jl;
  if (rk) window.roomKey  = rk;
  if (rid) window.roomId  = rid;
}
cacheHostFieldsFromDOM();

function hydrateHostPanel() {
  // If we already have them (because we were owner), just push to inputs
  if (window.joinLink && window.roomKey && window.roomId) {
    const jl = document.getElementById("joinLink");
    const rk = document.getElementById("roomKeyField");
    const rid = document.getElementById("roomIdField");
    if (jl)  jl.value  = window.joinLink;
    if (rk)  rk.value  = window.roomKey;
    if (rid) rid.value = window.roomId;
    return;
  }
  // Otherwise, request them from the previous host via E2E signal
  sendPlain({ type: "host_payload_request" });
}



// ---------- Local media wait ----------
function waitLocalMedia() {
  return new Promise((res) => {
    if (localStream) return res();
    const t = setInterval(() => { if (localStream) { clearInterval(t); res(); } }, 100);
  });
}

// ---------- Presence / Kick UI ----------
function ensureKickSelectExists() {
  if (!window.isHost) return null;
  const kickBtn = document.getElementById("hostKick");
  if (!kickBtn) return null;
  let sel = document.getElementById("kickSelect");
  if (!sel) {
    sel = document.createElement("select");
    sel.id = "kickSelect";
    sel.style.minWidth = "160px";
    sel.style.padding = "6px";
    sel.style.borderRadius = "8px";
    sel.style.border = "1px solid #333";
    sel.style.marginRight = "8px";
    kickBtn.parentNode.insertBefore(sel, kickBtn);
  }
  return sel;
}
function refreshKickList() {
  const sel = ensureKickSelectExists();
  if (!sel) return;
  const others = [...participants].filter(u => u !== username);
  sel.innerHTML = "";
  if (others.length === 0) {
    const opt = document.createElement("option"); opt.value = ""; opt.textContent = "No participants";
    sel.appendChild(opt); sel.disabled = true;
  } else {
    sel.disabled = false;
    for (const u of others) { const opt = document.createElement("option"); opt.value = u; opt.textContent = u; sel.appendChild(opt); }
  }
}

// ---------- Host-introduced handshakes ----------
function startPeerHandshake(otherUser) {
  const p = ensurePeer(otherUser);
  // Generate our DH keypair once
  if (!p.dhPrivate) {
    const privBytes = crypto.getRandomValues(new Uint8Array(32));
    p.dhPrivate = BigInt("0x" + Array.from(privBytes).map(b => b.toString(16).padStart(2,"0")).join(""));
    p.dhPublic  = modPow(GENERATOR, p.dhPrivate, PRIME);
  }
  // Start DH by sending our public
  sendPlainSignal(otherUser, { type: "dh_public", value: p.dhPublic.toString() });
}

// ---------- WebSocket lifecycle ----------
socket.onopen = async () => {
  console.log("[WS] open");
  await initIceServers();
  sendPlain({ type: "hello" });
};


function watchPC(user, pc) {
  pc.onconnectionstatechange = () => {
    console.log(`[RTC] ${user} connectionState = ${pc.connectionState}`);
  };
  pc.oniceconnectionstatechange = () => {
    console.log(`[ICE] ${user} iceConnectionState = ${pc.iceConnectionState}`);
  };
}



socket.onmessage = async (ev) => {
  const msg = JSON.parse(ev.data);

  // Host controls
  if (msg.type === "host_mute") {
    if (localStream) localStream.getAudioTracks().forEach(t => t.enabled = false);
    for (const u in peers) peers[u].pc.getSenders().forEach(s => { if (s.track?.kind === "audio") s.track.enabled = false; });
    isMuted = true; updateButtonsUI();
    const el = document.getElementById("banner"); if (el) el.textContent = "The host muted your microphone."; return;
  }
  if (msg.type === "host_kick" && msg.to === username) {
    alert("You have been removed by the host."); await hangup(false); return;
  }

  if (msg.type === "peer_joined") {
    const u = msg.user; if (!u || u === username) return;
    participants.add(u); refreshKickList();

    // System chat line
    appendChatLine(`${u} joined the room`, { system: true });
    window.playNotify && window.playNotify();


    if (window.isHost) {
      // Introduce newcomer to everyone else
      const others = [...participants].filter(x => x !== username && x !== u);
      for (const o of others) sendPlain({ type: "introduce_pair", a: u, b: o });
      // Host connects to newcomer too
      startPeerHandshake(u);
    } else {
      // Non-host: start handshake directly with newcomer (fast join)
      startPeerHandshake(u);
    }
    return;
  }

  if (msg.type === "peer_left") {
    const u = msg.user;
    participants.delete(u);
    refreshKickList();
    closePeer(u);

    if (u) appendChatLine(`${u} left the room`, { system: true });
    window.playNotify && window.playNotify();

    return;
  }

  // inside socket.onmessage AFTER you parse msg:
  if (msg.type === "host_payload_request") {
    // Only the current host should answer
    if (window.isHost && window.roomKey && window.joinLink && window.roomId) {
      const requester = msg.from; // who asked
      try {
        await sendSecure(requester, {
          type: "host_payload",
          roomId: window.roomId,
          roomKey: window.roomKey,
          joinLink: window.joinLink
        });
      } catch(e) { console.warn("[HOST] payload send failed:", e); }
    }
    return;
  }

  // ---- CHAT from server ----
  if (msg.type === "chat") {
    const from = msg.from || "Unknown";
    const text = msg.text || "";
    const isSelf = from === username;
    appendChatLine(text, { from, self: isSelf, system: false });
    if (!isSelf) window.playNotify && window.playNotify();
    return;
  }


  if (msg.type === "peer_list") {
    const list = msg.users || [];
    list.forEach(u => { if (u !== username) participants.add(u); });
    refreshKickList();

    // <-- NEW: set initial host based on server’s answer
    setHostUI(msg.host === username);

    // Existing intro logic…
    if (window.isHost) {
      const others = list.filter(u => u !== username);
      for (let i = 0; i < others.length; i++) {
        for (let j = i + 1; j < others.length; j++) {
          sendPlain({ type: "introduce_pair", a: others[i], b: others[j] });
        }
      }
      for (const u of others) startPeerHandshake(u);
    } else {
      for (const u of list) if (u !== username) startPeerHandshake(u);
    }
    return;
  }

  if (msg.type === "host_changed") {
    const newHost = msg.host || null;
    // flip UI
    setHostUI(newHost === username);
    return;
  }

  // Introductions (server should relay a 'signal' with {type:'intro', other:'name'})
  if (msg.type === "signal" && msg.data && msg.data.type === "intro" && msg.to === username) {
    const other = msg.data.other; if (other && other !== username) startPeerHandshake(other);
    return;
  }

  // Relayed signaling (STAR)
  if (msg.type === "signal" && msg.to === username && msg.from) {
    await handleSignalFrom(msg.from, msg.data);
  }
};

socket.onclose = () => { console.log("[WS] closed"); };

// ---------- Controls: Mute/Camera/Hangup ----------
let isMuted = false;
let isVideoOff = false;

function updateButtonsUI() {
  const btnMute   = document.getElementById("btnMute");
  const btnCamera = document.getElementById("btnCamera");
  if (btnMute)   { btnMute.textContent = isMuted ? "Unmute" : "Mute"; btnMute.setAttribute("aria-pressed", String(isMuted)); }
  if (btnCamera) { btnCamera.textContent = isVideoOff ? "Camera on" : "Camera off"; btnCamera.setAttribute("aria-pressed", String(isVideoOff)); }
}

// ----------- LIVE DEVICE SWITCHING -----------
async function switchMicrophone(deviceId) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return;

  const constraints = {
    audio: deviceId ? { deviceId: { exact: deviceId } } : true,
    video: false
  };

  let newStream;
  try {
    newStream = await navigator.mediaDevices.getUserMedia(constraints);
  } catch (err) {
    console.warn("[DEVICES] Failed to get new mic:", err);
    return;
  }

  const newTrack = newStream.getAudioTracks()[0];
  if (!newTrack) return;

  // Replace in localStream
  const oldTracks = localStream ? localStream.getAudioTracks() : [];
  oldTracks.forEach(t => {
    try { t.stop(); } catch {}
    if (localStream) localStream.removeTrack(t);
  });
  if (localStream) localStream.addTrack(newTrack);

  // Replace in all peer senders
  for (const u in peers) {
    const s = peers[u].pc.getSenders().find(x => x.track && x.track.kind === "audio");
    if (s) {
      try { await s.replaceTrack(newTrack); } catch (e) { console.warn("[DEVICES] replaceTrack mic failed:", e); }
    }
  }

  console.log("[DEVICES] Microphone switched to", deviceId || "default");
}

async function switchCamera(deviceId) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return;

  const constraints = {
    video: deviceId ? { deviceId: { exact: deviceId } } : true,
    audio: false
  };

  let newStream;
  try {
    newStream = await navigator.mediaDevices.getUserMedia(constraints);
  } catch (err) {
    console.warn("[DEVICES] Failed to get new camera:", err);
    return;
  }

  const newTrack = newStream.getVideoTracks()[0];
  if (!newTrack) return;

  // Stop old video tracks in localStream
  const oldTracks = localStream ? localStream.getVideoTracks() : [];
  oldTracks.forEach(t => {
    if (t !== blackTrack) { // keep blackTrack for camera-off mode
      try { t.stop(); } catch {}
      if (localStream) localStream.removeTrack(t);
    }
  });

  if (localStream) localStream.addTrack(newTrack);
  originalVideoTrack = newTrack;  // so toggleCamera keeps working

  // Update local preview (only if camera is ON)
  if (!isVideoOff && localVideo) {
    const preview = new MediaStream([newTrack]);
    // add audio tracks for preview if you want
    if (localStream) localStream.getAudioTracks().forEach(a => preview.addTrack(a));
    localVideo.srcObject = preview;
    try { await localVideo.play(); } catch {}
  }

  // Replace in all peer senders
  for (const u in peers) {
    const s = peers[u].pc.getSenders().find(x => x.track && x.track.kind === "video");
    if (s) {
      try { await s.replaceTrack(newTrack); } catch (e) { console.warn("[DEVICES] replaceTrack camera failed:", e); }
    }
  }

  console.log("[DEVICES] Camera switched to", deviceId || "default");
}

async function switchSpeakers(deviceId) {
  // Only works in browsers that support setSinkId (Chrome, Edge, some others) and HTTPS
  if (!("setSinkId" in HTMLMediaElement.prototype)) {
    console.warn("[DEVICES] setSinkId not supported in this browser");
    return;
  }

  const applyTo = [];

  // Remote tiles
  const remoteVideos = document.querySelectorAll("#remotes video");
  remoteVideos.forEach(v => applyTo.push(v));

  // Optionally also localScreen / localVideo if you want audio preview
  // (localVideo is muted by default, so usually unnecessary)

  for (const el of applyTo) {
    try {
      await el.setSinkId(deviceId || "");
    } catch (err) {
      console.warn("[DEVICES] setSinkId failed:", err);
    }
  }

  console.log("[DEVICES] Speakers switched to", deviceId || "default");
}


function toggleMute() {
  if (!localStream) return;
  const tracks = localStream.getAudioTracks();
  if (!tracks.length) return;
  const next = !tracks[0].enabled;
  tracks.forEach(t => t.enabled = next);
  for (const u in peers) peers[u].pc.getSenders().forEach(s => { if (s.track?.kind === "audio") s.track.enabled = next; });
  isMuted = !next; updateButtonsUI();
}

async function toggleCamera() {
  if (!originalVideoTrack) return;

  if (!isVideoOff) {
    // OFF
    for (const u in peers) {
      const s = peers[u].pc.getSenders().find(x => x.track?.kind === "video");
      if (s) await s.replaceTrack(blackTrack);
    }
    const preview = new MediaStream([blackTrack]);
    localStream.getAudioTracks().forEach(a => preview.addTrack(a));
    if (localVideo) { localVideo.srcObject = preview; try { await localVideo.play(); } catch {} }
    isVideoOff = true;

  } else {
    // ON
    isVideoOff = false;                     // flip first
    const onTrack = getCurrentVideoTrack(); // filtered/cam based on prefs

    for (const u in peers) {
      const s = peers[u].pc.getSenders().find(x => x.track?.kind === "video");
      if (s) await s.replaceTrack(onTrack);
    }

    if (localVideo) {
      localVideo.srcObject = (filteredStream || localStream);
      try { await localVideo.play(); } catch {}
    }
  }

  updateButtonsUI();
}



async function hangup(sendBye = true) {
  if (sendBye) {
    for (const u in peers) {
      try { await sendSecure(u, { type: "bye" }); } catch {}
    }
  }
  try { localStream?.getTracks().forEach(t => t.stop()); } catch {}
  try { blackTrack?.stop(); } catch {}
  try { screenStream?.getTracks().forEach(t => t.stop()); } catch {}  // <--- NEW

  for (const u of Object.keys(peers)) closePeer(u);
  try { socket.close(); } catch {}
  window.location.href = "/lobby";
}

async function startScreenShare() {
  if (screenStream) return; // already sharing

  try {
    const stream = await navigator.mediaDevices.getDisplayMedia({
      video: { frameRate: 15 },
      audio: false
    });

    screenStream = stream;
    screenTrack  = stream.getVideoTracks()[0];

    // Local preview
    if (localScreen) {
      localScreen.srcObject = screenStream;
      try { await localScreen.play(); } catch {}
    }

    // Add to all existing peers
    for (const u in peers) {
      const pc = peers[u].pc;
      const sender = pc.addTrack(screenTrack, screenStream);
      if (!screenSenders[u]) screenSenders[u] = [];
      screenSenders[u].push(sender);
    }

    // If user stops via browser UI (Stop sharing button)
    screenTrack.addEventListener("ended", () => {
      stopScreenShare();
    });

    console.log("[SCREEN] Sharing started");
  } catch (e) {
    console.warn("[SCREEN] getDisplayMedia failed:", e);
  }
}

function stopScreenShare() {
  if (!screenStream) return;

  console.log("[SCREEN] Stopping share");

  try {
    screenStream.getTracks().forEach(t => t.stop());
  } catch {}

  if (localScreen) {
    localScreen.srcObject = null;
  }

  // Remove senders from all peers
  for (const u in screenSenders) {
    const list = screenSenders[u] || [];
    for (const sender of list) {
      try {
        const pc = peers[u]?.pc;
        if (pc) pc.removeTrack(sender);
      } catch (e) {
        console.warn("[SCREEN] removeTrack failed:", e);
      }
    }
    screenSenders[u] = [];
  }

  screenStream = null;
  screenTrack  = null;

  // 👇 REMOVE MY OWN SCREEN TILE (THIS IS THE PART YOU ASKED “WHERE?”)
  const mine = document.getElementById(`screen-${username}`);
  if (mine && mine.parentElement) mine.parentElement.remove();
}



// ---------- Wire UI ----------
window.addEventListener("DOMContentLoaded", () => {
  // ----- MEDIA CONTROLS -----
  const btnMute   = document.getElementById("btnMute");
  const btnCamera = document.getElementById("btnCamera");
  const btnHangup = document.getElementById("btnHangup");

  if (btnMute) btnMute.addEventListener("click", (e) => {
    e.preventDefault(); e.stopPropagation();
    console.log("[UI] Mute clicked");
    toggleMute();
  });

  if (btnCamera) btnCamera.addEventListener("click", async (e) => {
    e.preventDefault(); e.stopPropagation();
    console.log("[UI] Camera clicked");
    await toggleCamera();
  });

  if (btnHangup) btnHangup.addEventListener("click", async (e) => {
    e.preventDefault(); e.stopPropagation();
    console.log("[UI] Hangup clicked");
    if (confirm("Are you sure you want to disconnect from the call?")) {
      await hangup(true);
    }
  });

  const btnShare = document.getElementById("btnShare");

  if (btnShare) btnShare.addEventListener("click", async (e) => {
    e.preventDefault(); e.stopPropagation();
    console.log("[UI] Share screen clicked");

    if (!screenStream) {
      await startScreenShare();
      btnShare.textContent = "Stop share";
    } else {
      stopScreenShare();
      btnShare.textContent = "Share screen";
    }
  });

    // ----- CHAT -----
  if (chatForm && chatInput) {
    chatForm.addEventListener("submit", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const text = chatInput.value.trim();
      if (!text) return;

      // Send to room via signaling server
      socket.send(JSON.stringify({
        type: "chat",
        text,
        // 'to' can be added later for private messages
      }));
      chatInput.value = "";
    });
  }

    // ----- DEVICE SELECTORS -----
  if (micSelect) {
    micSelect.addEventListener("change", () => {
      const id = micSelect.value || null;
      switchMicrophone(id);
    });
  }

  if (camSelect) {
    camSelect.addEventListener("change", () => {
      const id = camSelect.value || null;
      switchCamera(id);
    });
  }

  if (spkSelect) {
    spkSelect.addEventListener("change", () => {
      const id = spkSelect.value || null;
      switchSpeakers(id);
    });
  }




  // ----- HOST CONTROLS -----
  const muteAllBtn  = document.getElementById("hostMuteAll");
  const kickBtn     = document.getElementById("hostKick");
  const transferBtn = document.getElementById("hostTransfer");

  if (muteAllBtn)  muteAllBtn.addEventListener("click", (e) => {
    e.preventDefault(); e.stopPropagation();
    if (!window.isHost) return;
    sendPlain({ type: "host_mute_all" });
  });

  if (kickBtn)     kickBtn.addEventListener("click", (e) => {
    e.preventDefault(); e.stopPropagation();
    if (!window.isHost) return;
    const sel = document.getElementById("kickSelect");
    let target = sel && !sel.disabled ? sel.value : "";
    if (!target) target = prompt("Enter participant username to kick:");
    if (target) sendPlain({ type: "host_kick", target });
  });

  if (transferBtn) transferBtn.addEventListener("click", (e) => {
    e.preventDefault(); e.stopPropagation();
    if (!window.isHost) return;
    const sel = document.getElementById("kickSelect");
    let toUser = sel && !sel.disabled ? sel.value : "";
    if (!toUser) toUser = prompt("Make host (username):");
    if (toUser && toUser !== username) sendPlain({ type: "transfer_host", to: toUser });
  });

  ensureKickSelectExists();
  refreshKickList();
  updateButtonsUI();  // sets initial button labels (Mute/Unmute, Camera on/off)
});
