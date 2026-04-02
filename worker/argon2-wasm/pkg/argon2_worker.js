/* @ts-self-types="./argon2_worker.d.ts" */

import * as wasm from "./argon2_worker_bg.wasm";
import { __wbg_set_wasm } from "./argon2_worker_bg.js";
__wbg_set_wasm(wasm);

export {
    argon2id_derive
} from "./argon2_worker_bg.js";
