/**
 * @fileoverview 给指向 sspai CDN 的请求注入 Referer 头
 */

let headers = $request.headers;
headers['Referer'] = 'https://sspai.com/';

$done({ headers });