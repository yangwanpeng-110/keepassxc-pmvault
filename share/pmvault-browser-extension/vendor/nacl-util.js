// Minimal encoding helpers shared by the service worker (classic worker,
// loaded via importScripts). Works on top of tweetnacl's Uint8Array API.
(function (global) {
  "use strict";

  function utf8ToBytes(str) {
    return new TextEncoder().encode(str);
  }

  function bytesToUtf8(bytes) {
    return new TextDecoder().decode(bytes);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const len = bin.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
  }

  function bytesToBase64(bytes) {
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }

  function randomBase64(lenBytes) {
    const b = new Uint8Array(lenBytes);
    crypto.getRandomValues(b);
    return bytesToBase64(b);
  }

  global.PmpUtil = {
    utf8ToBytes,
    bytesToUtf8,
    base64ToBytes,
    bytesToBase64,
    randomBase64
  };
})(self);
