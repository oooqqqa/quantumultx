/**
 * @fileoverview 将 Surge 规则集转换为 QuantumultX 支持的规则格式，支持参数解析与 domain-set 特殊逻辑
 * @supported Quantumult X (v1.0.8-build253)
 * 解析 URL 中的参数，例如 https://example.com/rules.list#policy=direct&domain-set=true
 */

function parseParams(url) {
  const paramStr = url.split('#')[1] || '';
  return paramStr.split('&').reduce((params, pair) => {
    const [key, value] = pair.split('=');
    if (key) params[key.trim()] = value ? value.trim() : '';
    return params;
  }, {});
}

const params = parseParams($resource.link || '');
const policy = params['policy'] || 'proxy';
const useDomainSet = params['domain-set'] === 'true';

// 类型映射表：Surge → Quantumult X
const typeMap = {
  'DOMAIN':         'host',
  'DOMAIN-SUFFIX':  'host-suffix',
  'DOMAIN-KEYWORD': 'host-keyword',
  'IP-CIDR':        'ip-cidr',
  'IP-CIDR6':       'ip6-cidr',
  'IP-ASN':         'ip-asn'
};

// 处理规则内容
const lines = ($resource.content || '').split(/\r?\n/);
const output = [];

for (const raw of lines) {
  const line = raw.trim();

  // 跳过空行与注释
  if (!line || line.startsWith('#') || line.startsWith('//') || line.startsWith(';')) continue;

  // 特殊 domain-set 模式下的处理逻辑
  if (useDomainSet) {
    if (line.startsWith('.')) {
      // 例如 `.example.com` → `host-suffix,example.com,${policy}`
      output.push(`host-suffix,${line.slice(1)},${policy}`);
    } else {
      // 例如 `example.com` → `host,example.com,${policy}`
      output.push(`host,${line},${policy}`);
    }
  } else {
    // 常规映射处理
    const parts = line.split(',').map(p => p.trim());
    const key = (parts[0] || '').toUpperCase();
    const target = parts[1];
    if (typeMap[key] && target) {
      output.push(`${typeMap[key]},${target},${policy}`);
    }
  }
}

// 返回转换结果
$done({ content: output.join('\n') });