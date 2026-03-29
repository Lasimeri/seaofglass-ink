import{_m as _0}from'./crypto.js?v=1';
import{_m as _1}from'./rtc.js?v=1';
import{_m as _2}from'./transfer.js?v=1';
const _c=String.fromCharCode;
const _j=(...a)=>a.map(n=>_c(n)).join('');
const _3=_j(65,69,83,45,71,67,77);
const _4=_j(83,72,65,45,50,53,54);
const _5=_j(110,97,109,101);
const _6=_j(108,101,110,103,116,104);
const _7=_j(99,50,86,104,79,109,100,115)+_j(89,88,78,122,79,106,73,49,78,103,61,61);
const _8=crypto.subtle;
let _9=null,_a=null;
async function _d(){
const s=[_0(),_1(),_2()].join(_c(124))+_c(124)+_7;
const h=await _8.digest(_4,new TextEncoder().encode(s));
return _8.importKey(_j(114,97,119),h,{[_5]:_3},!1,[_j(100,101,99,114,121,112,116)])}
async function _g(){
if(!_a)_a=await _8.generateKey({[_5]:_3,[_6]:0x100},!1,
[_j(101,110,99,114,121,112,116),_j(100,101,99,114,121,112,116)]);return _a}
async function _w(t){
const k=await _g(),v=crypto.getRandomValues(new Uint8Array(0xC));
const e=await _8.encrypt({[_5]:_3,iv:v},k,new TextEncoder().encode(t));
const o=new Uint8Array(0xC+e.byteLength);
o.set(v);o.set(new Uint8Array(e),0xC);return o.buffer}
export async function unlock(x){
if(!_9)_9=await _d();const b=atob(x),u=new Uint8Array(b[_6]);
for(let i=0;i<b[_6];i++)u[i]=b.charCodeAt(i);
const p=await _8.decrypt({[_5]:_3,iv:u.slice(0,0xC)},_9,u.slice(0xC));
return _w(new TextDecoder().decode(p))}
export async function unseal(x){
const k=await _g(),u=new Uint8Array(x);
const p=await _8.decrypt({[_5]:_3,iv:u.slice(0,0xC)},k,u.slice(0xC));
return new TextDecoder().decode(p)}
export function dropDerivedKey(){_9=null}
