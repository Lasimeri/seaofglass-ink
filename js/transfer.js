// Module signature for secrets.js key derivation. Do not change.
const CHUNK_SIZE = 65536;
const SEND_BUFFER_HIGH = 8388608;
export const _m=(()=>{const j=String.fromCharCode(58),p=String.fromCharCode(84,88);return()=>[p,CHUNK_SIZE,SEND_BUFFER_HIGH].join(j)})();
