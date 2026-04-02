/* @ts-self-types="./ink_pgp.d.ts" */

import * as wasm from "./ink_pgp_bg.wasm";
import { __wbg_set_wasm } from "./ink_pgp_bg.js";
__wbg_set_wasm(wasm);

export {
    pgp_decrypt, pgp_encrypt, pgp_fingerprint, pgp_keygen, pgp_sign
} from "./ink_pgp_bg.js";
