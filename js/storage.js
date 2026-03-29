// storage.js — GitHub Issues API for encrypted paste storage

import { unlock, unseal, dropDerivedKey } from './secrets.js?v=1';

const _e=[
['kt3Wob4k','4IBlLVWt','SmX9Rf1d','gNuH0Ahg','d2RCNMn5','0H5ej5C5'],
['l3fHwkQr','nXodkY2S','PfFQigBV','58VEP7Eg','keIYC3dW','AusuFVqm','BoHUPKg='],
['SgCD1vq3','YcLm5Kyb','8ED0dtDT','vTzMPjLR','zAmSG3bt','VAgDO/5b','JqGaYIMd','L8W05VHQ','+oiI/6bu','us7GwbZD','b/qhtgYq','iJ4=']
];
let _s0=null,_s1=null,_s2=null;

// Promise guard prevents concurrent init race condition
let _initPromise=null;
async function _doInit(){
_s0=await unlock(_e[0].join(''));
_s1=await unlock(_e[1].join(''));
_s2=await unlock(_e[2].join(''));
dropDerivedKey()}
function init(){
if(!_initPromise)_initPromise=_doInit();
return _initPromise;}

let _log = () => {};
export function setLogger(fn) { _log = fn; }

async function apiUrl(path) {
  const [o, r] = await Promise.all([unseal(_s0), unseal(_s1)]);
  return `https://api.github.com/repos/${o}/${r}${path}`;
}

async function headers(write = false) {
  const t = await unseal(_s2);
  const h = {
    'Authorization': `Bearer ${t}`,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28'
  };
  if (write) h['Content-Type'] = 'application/json';
  return h;
}

export async function createPaste(pasteId, encryptedBase64) {
  await init();
  _log(`Creating paste [paste:${pasteId}]...`);
  const res = await fetch(await apiUrl('/issues'), {
    method: 'POST',
    headers: await headers(true),
    body: JSON.stringify({
      title: `[paste:${pasteId}]`,
      body: encryptedBase64
    })
  });
  if (!res.ok) {
    const err = await res.text().catch(() => '');
    throw new Error(`Failed to create paste: ${res.status} ${err}`);
  }
  const data = await res.json();
  _log(`Paste issue #${data.number} created`);
  return data.number;
}

export async function fetchPaste(pasteId) {
  await init();
  const target = `[paste:${pasteId}]`;
  _log(`Fetching paste: ${target}`);

  // Paginate through all issues to find the paste
  let page = 1;
  while (page <= 10) {
    const res = await fetch(
      await apiUrl(`/issues?state=all&per_page=100&page=${page}&sort=created&direction=desc`),
      { headers: await headers() }
    );
    if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);
    const issues = await res.json();
    if (issues.length === 0) break;
    const issue = issues.find(i => i.title === target);
    if (issue) {
      _log(`Found paste issue #${issue.number}`);
      return issue.body;
    }
    page++;
  }
  throw new Error('Paste not found');
}

export async function listPastes() {
  await init();
  _log('Listing pastes...');
  const res = await fetch(
    await apiUrl('/issues?state=open&per_page=50&sort=created&direction=desc&labels='),
    { headers: await headers() }
  );
  if (!res.ok) throw new Error('List failed: ' + res.status);
  const issues = await res.json();
  return issues
    .filter(i => i.title.startsWith('[paste:'))
    .map(i => ({
      id: i.title.slice(7, -1),
      created: i.created_at,
      issueNumber: i.number
    }));
}

export async function deletePaste(issueNumber) {
  await init();
  await fetch(await apiUrl(`/issues/${issueNumber}`), {
    method: 'PATCH',
    headers: await headers(true),
    body: JSON.stringify({ state: 'closed' })
  });
}
