/* 電波人間のRPG FREE! (3DS) code math: decoder/generator for the 16-character
   codes, ported from tools/denpa_code.py (reverse engineered from code.bin
   v17.20.0). Pure functions; works in the browser and in Node. */
(function (root) {
  'use strict';

  var ALPHABET = 'C341PV0BTXLJYKM8FDHRQ7GNAEW6U592';
  var K1 = 0x43BD527F, K2 = 0x950C6D7F, H1 = 0x9FA5, H2 = 0x302D;

  function ror(x, n) { return (x >>> n) | (x << (32 - n)); }

  var SHA_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function sha256(msg) {
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var bytes = msg.slice(), bitLen = msg.length * 8, i, t;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    for (i = 7; i >= 0; i--) bytes.push(Math.floor(bitLen / Math.pow(2, 8 * i)) & 0xff);
    var w = new Array(64);
    for (var off = 0; off < bytes.length; off += 64) {
      for (t = 0; t < 16; t++) {
        w[t] = ((bytes[off + 4 * t] << 24) | (bytes[off + 4 * t + 1] << 16) |
                (bytes[off + 4 * t + 2] << 8) | bytes[off + 4 * t + 3]) >>> 0;
      }
      for (t = 16; t < 64; t++) {
        var x = w[t - 15], y = w[t - 2];
        var s0 = (ror(x, 7) ^ ror(x, 18) ^ (x >>> 3)) >>> 0;
        var s1 = (ror(y, 17) ^ ror(y, 19) ^ (y >>> 10)) >>> 0;
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (t = 0; t < 64; t++) {
        var S1 = (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) >>> 0;
        var ch = ((e & f) ^ (~e & g)) >>> 0;
        var t1 = (h + S1 + ch + SHA_K[t] + w[t]) >>> 0;
        var S0 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) >>> 0;
        var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
        var t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    var out = [];
    for (i = 0; i < 8; i++) out.push((H[i] >>> 24) & 255, (H[i] >>> 16) & 255, (H[i] >>> 8) & 255, H[i] & 255);
    return out;
  }

  function rev32(x) {
    x = ((x >>> 1) & 0x55555555) | ((x & 0x55555555) << 1);
    x = ((x >>> 2) & 0x33333333) | ((x & 0x33333333) << 2);
    x = ((x >>> 4) & 0x0F0F0F0F) | ((x & 0x0F0F0F0F) << 4);
    x = ((x >>> 8) & 0x00FF00FF) | ((x & 0x00FF00FF) << 8);
    return ((x >>> 16) | (x << 16)) >>> 0;
  }
  function rev16(x) {
    x = ((x >>> 1) & 0x5555) | ((x & 0x5555) << 1);
    x = ((x >>> 2) & 0x3333) | ((x & 0x3333) << 2);
    x = ((x >>> 4) & 0x0F0F) | ((x & 0x0F0F) << 4);
    x = ((x >>> 8) & 0x00FF) | ((x & 0x00FF) << 8);
    return x & 0xFFFF;
  }
  // The constant pairs are modular inverses, so each mixer is its own inverse.
  function mix32(x) { return Math.imul(rev32(Math.imul(x, K1) >>> 0), K2) >>> 0; }
  function mix16(x) { return (rev16((x * H1) & 0xFFFF) * H2) & 0xFFFF; }

  function get32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
  function put32(b, o, v) { b[o] = v & 255; b[o + 1] = (v >>> 8) & 255; b[o + 2] = (v >>> 16) & 255; b[o + 3] = (v >>> 24) & 255; }
  function get16(b, o) { return b[o] | (b[o + 1] << 8); }
  function put16(b, o, v) { b[o] = v & 255; b[o + 1] = (v >>> 8) & 255; }

  // order used by the game when decoding; generating applies the reverse order
  function unscramble(b) {
    put32(b, 6, mix32(get32(b, 6))); put32(b, 0, mix32(get32(b, 0)));
    put32(b, 4, mix32(get32(b, 4))); put16(b, 8, mix16(get16(b, 8)));
    return b;
  }
  function scramble(b) {
    put16(b, 8, mix16(get16(b, 8))); put32(b, 4, mix32(get32(b, 4)));
    put32(b, 0, mix32(get32(b, 0))); put32(b, 6, mix32(get32(b, 6)));
    return b;
  }

  function bytesToCode(b) {
    var n = BigInt(0), s = '', i;
    for (i = 0; i < 10; i++) n = (n << BigInt(8)) | BigInt(b[i]);
    for (i = 0; i < 16; i++) s += ALPHABET.charAt(Number((n >> BigInt(5 * (15 - i))) & BigInt(31)));
    return s;
  }
  function codeToBytes(code) {
    var n = BigInt(0), i;
    for (i = 0; i < 16; i++) {
      var v = ALPHABET.indexOf(code.charAt(i));
      if (v < 0) return null;
      n = (n << BigInt(5)) | BigInt(v);
    }
    var b = new Array(10);
    for (i = 9; i >= 0; i--) { b[i] = Number(n & BigInt(255)); n = n >> BigInt(8); }
    return b;
  }

  function normalizeCode(s) { return String(s || '').toUpperCase().replace(/[\s\-]/g, ''); }

  function encode(type, payload, ver) {
    ver = ver || { major: 0, minor: 0, build: 0 };
    var cs = sha256(payload)[0];
    var b = [0, 0, 0, 0, 0].concat(payload);
    put32(b, 0, ((cs << 24) | ((ver.build & 0x3FFF) << 10) | (ver.minor & 0x3FF)) >>> 0);
    b[4] = ((ver.major & 0x3F) << 2) | (type & 3);
    var plain = b.slice();
    return { code: bytesToCode(scramble(b)), plain: plain };
  }

  // Version recorded in a final-version save (title screen "Ver.1.17"). Field widths in a
  // code: major 6 bits, minor 10 bits, build 14 bits.
  var FINAL_VERSION = { major: 1, minor: 17, build: 0 };
  var VERSION_MAX = { major: 63, minor: 1023, build: 16383 };

  function clampVersion(v) {
    v = v || {};
    function n(x, max) { x = Math.floor(Number(x)); return isFinite(x) ? Math.max(0, Math.min(max, x)) : 0; }
    return { major: n(v.major, VERSION_MAX.major), minor: n(v.minor, VERSION_MAX.minor), build: n(v.build, VERSION_MAX.build) };
  }
  function formatVersion(v) { return v.major + '.' + v.minor + '.' + v.build; }
  // The game's check (FUN_001b53d4): the code's required version must not be newer than the
  // game's own, compared as (major*1000 + minor, build). 0.0.0 therefore always passes.
  function versionAccepted(codeVer, gameVer) {
    var g = gameVer || FINAL_VERSION;
    var a = codeVer.major * 1000 + codeVer.minor, b = g.major * 1000 + g.minor;
    return a < b || (a === b && codeVer.build <= g.build);
  }

  function decode(input) {
    var code = normalizeCode(input);
    if (code.length !== 16) return { error: 'length', length: code.length };
    for (var i = 0; i < 16; i++) {
      if (ALPHABET.indexOf(code.charAt(i)) < 0) return { error: 'char', at: i, ch: code.charAt(i) };
    }
    var b = unscramble(codeToBytes(code));
    var u = get32(b, 0), payload = b.slice(5, 10);
    var info = {
      code: code, plain: b, checksumOk: sha256(payload)[0] === b[3], type: b[4] & 3,
      version: { major: b[4] >> 2, minor: u & 0x3FF, build: (u >>> 10) & 0x3FFF }, payload: payload
    };
    if (info.type === 0) { info.recordIndex = get32(b, 5); info.byte9 = b[9]; }
    if (info.type === 2) { info.fold = b[5] | (b[9] << 8); info.action = b[6]; info.counter = b[7]; info.byte8 = b[8]; }
    return info;
  }

  // In game the support number shows as XXXX-XXXX-XXXX-XXXX (hex). The game folds
  // the 64-bit value into 16 bits; that equals the four groups' sum mod 0x10000.
  function parseSupport(text) {
    var s = String(text || '').toUpperCase().replace(/[\s\-]/g, '');
    if (s === '') return { empty: true, groups: [0, 0, 0, 0], fold: 0, display: '0000-0000-0000-0000' };
    if (!/^[0-9A-F]+$/.test(s)) return { error: 'char' };
    if (s.length > 16) return { error: 'length' };
    s = ('0000000000000000' + s).slice(-16);
    var groups = [0, 4, 8, 12].map(function (o) { return parseInt(s.substr(o, 4), 16); });
    var fold = (groups[0] + groups[1] + groups[2] + groups[3]) & 0xFFFF;
    return { empty: false, groups: groups, fold: fold, display: s.match(/.{4}/g).join('-') };
  }

  function actionCode(action, fold, counter, ver) {
    return encode(2, [fold & 255, action & 255, counter & 255, 0, (fold >>> 8) & 255], ver);
  }
  function commonCode(index, ver) {
    return encode(0, [index & 255, (index >>> 8) & 255, (index >>> 16) & 255, (index >>> 24) & 255, 0], ver);
  }

  // Support-only fix actions (CodeSystemAction). bound = needs the support-number fold;
  // counter = how the one-time counter works; limit = max successful uses.
  var ACTIONS = [
    { n: 1, name: 'セーブ異常判定の解除', desc: '「セーブデータが壊れている・改変された・最後にセーブされたものではない」の判定を解除し、正常に戻す。中断データも認証をつけ直す。', bound: true, counter: 'none', abnormalOk: true },
    { n: 2, name: '内部データの作り直し', desc: '内部データを作り直してセーブする。くわしい対象は不明。', bound: true, counter: 'nibble', limit: 16 },
    { n: 3, name: '配置アイテムの回収', desc: '20枠の配置アイテムを持ち物へ戻し、配置データを初期化する(Ver.1.8のインテリア不具合対応と推定)。', bound: true, counter: 'nibble', limit: 16 },
    { n: 4, name: 'パーティの割当解除', desc: 'パーティ最大8人の各8枠の割当を外す(装備と推定)。外すものがなければ「必要ありません」になり、回数も進まない。', bound: true, counter: 'nibble', limit: 16 },
    { n: 5, name: '電波人間データの修復', desc: '電波人間データの重複フラグ・状態値・所持数のずれを直す。サポート番号に関係なく全員同じコード。', bound: false, counter: 'zero' },
    { n: 6, name: '更新データの削除と再起動', desc: '更新データ(0004000E00125D00)を削除して再起動する。あとで更新データの入れ直しが必要。サポート番号に関係なく全員同じコード。', bound: false, counter: 'zero', abnormalOk: true, danger: true },
    { n: 7, name: 'すれちがい通信の再チェック', desc: '次にタイトル画面へ戻ったとき、すれちがい通信のチェックをやり直す(プレゼントはもらえない)。', bound: true, counter: 'zero' },
    { n: 8, name: 'ジュエル +1', desc: 'ジュエルを1つ受け取る。', bound: true, counter: 'count', limit: 15 },
    { n: 9, name: 'ジュエル +2', desc: 'ジュエルを2つ受け取る。', bound: true, counter: 'count', limit: 10 },
    { n: 10, name: 'ジュエル +3', desc: 'ジュエルを3つ受け取る。', bound: true, counter: 'count', limit: 5 },
    { n: 11, name: 'ジュエル +4', desc: 'ジュエルを4つ受け取る。', bound: true, counter: 'count', limit: 5 },
    { n: 12, name: 'ジュエル +5', desc: 'ジュエルを5つ受け取る。', bound: true, counter: 'count', limit: 3 }
  ];

  // campaignCodeLocal_JP.bin records usable from the normal code input (CodeCommon)
  var LOCAL = [
    [0, 0, 0, 'Ver.1.6更新記念', 'ジュエル×1', 'H1A6CJYFN3R73WUH'],
    [1, 1, 1, 'Miiverseフォロワー1万人', 'ジュエル×1', 'P8YE02HK5E4KR2VC'],
    [2, 9, 2, '1周年記念(2015/7/23)', 'ノビノビタケノコ', 'H7VPPRB8V8U1VG4H'],
    [3, 10, 2, '1周年記念(2015/7/23)', 'みつまたのやり', 'VB9DPTY90YQVLNV2'],
    [4, 11, 2, '1周年記念(2015/7/23)', 'えいゆうのつるぎ', '948L3HNCGYNW3M0U'],
    [5, 12, 2, '1周年記念(2015/7/23)', 'ももいろにゅうしぞう', 'RN8K5T252WG2TAEY'],
    [6, 13, 2, '1周年記念(2015/7/23)', 'きんのスプリンクラー', 'TQ368QU4B7RTTMEF'],
    [7, 3, 3, 'フォロワー1万5千人', 'ジュエル×1', 'X2B87Y0PBQBA139L'],
    [8, 14, 4, '選択式シリアルコード', 'ドリドリタケノコ', ''],
    [9, 15, 4, '選択式シリアルコード', 'ノビノビタケノコ', ''],
    [10, 16, 4, '選択式シリアルコード', 'ナンバーワン', 'MYYK08GHBC8N9KAQ'],
    [11, 17, 4, '選択式シリアルコード', 'トリプルシークレット', ''],
    [12, 18, 4, '選択式シリアルコード', 'きんピカはなもぐらぞう', ''],
    [13, 19, 5, '応援グッズ(2016/3/16)', 'ジュエル×3', 'FWUA7RWJC53HABHM'],
    [14, 20, 5, '応援グッズ(2016/3/16)', 'ノビノビタケノコ', 'HUE9U66L3TW62HE7'],
    [15, 21, 5, '応援グッズ(2016/3/16)', 'しゅっせいダケ', 'BT5RG1UU9L6T4LHA'],
    [16, 22, 5, '応援グッズ(2016/3/16)', '10カラットダイヤ', '043J8ALE9A8E1CUV'],
    [17, 23, 5, '応援グッズ(2016/3/16)', 'ミラースーツ', 'X9C89RN65H1A4KNA'],
    [18, 24, 6, 'フォロワー2万人', 'ジュエル×1', 'LQKPUJP0K8VNH4J2'],
    [19, 25, 7, '', '電波人間プレゼント(#131)', ''],
    [20, 26, 8, '', '電波人間プレゼント(#132)', ''],
    [21, 27, 9, '2周年記念(2016/7/23)', 'ノビノビタケノコ', ''],
    [22, 28, 9, '2周年記念(2016/7/23)', 'しろいタキシード', 'CQFDH0MGAAH5NAUX'],
    [23, 29, 9, '2周年記念(2016/7/23)', 'しゃちほこ', ''],
    [24, 30, 9, '2周年記念(2016/7/23)', 'おおきなダイヤ', ''],
    [25, 31, 9, '2周年記念(2016/7/23)', 'おはなドールのぞう', 'VFE0NWH80NNK5WVE'],
    [26, 32, 10, 'フォロワー2万5千人', 'ジュエル×1', 'QY8TP3RM34TDXQK4'],
    [27, 33, 11, 'シリーズ5周年記念(2017/2/1)', 'ジュエル×5', '6UXFQ97C8X2G9M5X'],
    [28, 34, 11, 'シリーズ5周年記念(2017/2/1)', 'ドリドリタケノコ', 'C2U3FYV531VHGYJQ'],
    [29, 35, 11, 'シリーズ5周年記念(2017/2/1)', 'てっかまき', 'KH40DWB28JA3LPVB'],
    [30, 36, 11, 'シリーズ5周年記念(2017/2/1)', 'みがわりくん', '3HL31RYPFF3916CT'],
    [31, 37, 11, 'シリーズ5周年記念(2017/2/1)', 'きんのダルマ', 'FKGA4473HXVYLCVX'],
    [32, 38, 12, 'フォロワー3万人', 'ジュエル×1', ''],
    [33, 39, 13, '', 'エメラルドのはのぞう', ''],
    [34, 40, 13, '', 'サファイアのはのぞう', ''],
    [35, 41, 13, '', 'ルビーのはのぞう', ''],
    [36, 42, 13, '', 'アメジストのはのぞう', ''],
    [37, 43, 13, '', 'トパーズのはのぞう', ''],
    [38, 44, 14, '3周年記念(2017/7/15)', 'しゅっせいダケ ×2', '39AK1L6YPBQKHNNB'],
    [39, 45, 14, '3周年記念(2017/7/15)', 'ドリドリタケノコ', '5RQP63FEV72KAMLG'],
    [40, 46, 14, '3周年記念(2017/7/15)', 'ミラーシールド', 'AYAAVW56P5AB24NH'],
    [41, 47, 14, '3周年記念(2017/7/15)', 'ちょうきょうのムチ', '07N2R46W8RQ0UF2X'],
    [42, 48, 14, '3周年記念(2017/7/15)', 'だいダメージだま', 'VM6BLNQTWQTQWXMW'],
    [43, 49, 15, 'フォロワー3万5千人', 'ジュエル×1', ''],
    [44, 50, 16, 'フォロワー4万人', 'ジュエル×1', ''],
    [45, 51, 17, 'フォロワー4万5千人', 'ジュエル×1', ''],
    [46, 52, 18, 'フォロワー5万人', 'ジュエル×1', ''],
    [47, 53, 19, 'フォロワー5万5千人', 'ジュエル×1', ''],
    [48, 54, 20, 'フォロワー6万人', 'ジュエル×1', ''],
    [49, 55, -1, 'オフラインチェックイン(2023/3/30)', 'サービス終了モードに切り替え(フラグ676)', 'A4J8Y13ML7TAWWE1']
  ].map(function (r) { return { no: r[0], id: r[1], group: r[2], campaign: r[3], reward: r[4], official: r[5] }; });
  // Official codes carry the version they were issued for.
  LOCAL.forEach(function (r) { r.officialVersion = r.official ? decode(r.official).version : null; });

  var api = {
    ALPHABET: ALPHABET, ACTIONS: ACTIONS, LOCAL: LOCAL,
    sha256: sha256, mix32: mix32, mix16: mix16, encode: encode, decode: decode,
    parseSupport: parseSupport, actionCode: actionCode, commonCode: commonCode, normalizeCode: normalizeCode,
    FINAL_VERSION: FINAL_VERSION, VERSION_MAX: VERSION_MAX,
    clampVersion: clampVersion, formatVersion: formatVersion, versionAccepted: versionAccepted
  };
  root.DenpaCode = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
