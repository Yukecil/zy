/**
 * Cloudflare Worker: secure GitHub config publisher.
 * Required Worker secrets: ADMIN_PASSWORD, GITHUB_TOKEN
 * Required Worker variables: GITHUB_REPO (e.g. Yukecil/zy), ALLOWED_ORIGIN (e.g. https://your-site.pages.dev)
 * Deploy this Worker separately. Never put these secrets in HTML/JS.
 */
const corsHeaders = origin => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Vary": "Origin"
});
function response(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders(origin) }
  });
}
function allowedOrigin(request, env) {
  const origin = request.headers.get("Origin") || "";
  return origin && origin === env.ALLOWED_ORIGIN ? origin : "";
}
function validConfig(c) {
  if (!c || typeof c !== "object" || Array.isArray(c)) return false;
  const keys = ["avatarUrl","userNameMain","userNameSub","tgUsername","emailAddress","tool1Icon","tool1Title","tool1Desc","tool1Url","tool2Icon","tool2Title","tool2Desc","tool2Url","usdtAddress"];
  if (Object.keys(c).some(k => !keys.includes(k))) return false;
  for (const k of keys) if (typeof (c[k] ?? "") !== "string" || (c[k] ?? "").length > 2000) return false;
  for (const k of ["avatarUrl","tool1Url","tool2Url"]) {
    const value = c[k];
    if (value) { try { if (!["http:","https:"].includes(new URL(value).protocol)) return false; } catch { return false; } }
  }
  return true;
}
export default {
  async fetch(request, env) {
    const origin = allowedOrigin(request, env);
    if (request.method === "OPTIONS") {
      if (!origin) return new Response(null, {status: 403});
      return new Response(null, {status: 204, headers: corsHeaders(origin)});
    }
    if (!origin) return new Response("Forbidden origin", {status: 403});
    if (request.method !== "POST") return response({ok:false,error:"Method not allowed"},405,origin);
    const path = new URL(request.url).pathname;
    let body;
    try { body = await request.json(); } catch { return response({ok:false,error:"Invalid JSON"},400,origin); }
    if (typeof env.ADMIN_PASSWORD !== "string" || !env.ADMIN_PASSWORD || typeof env.GITHUB_TOKEN !== "string" || !env.GITHUB_TOKEN) {
      return response({ok:false,error:"Worker secrets are not configured"},500,origin);
    }
    if (typeof body.password !== "string" || body.password !== env.ADMIN_PASSWORD) {
      return response({ok:false,error:"密码错误"},401,origin);
    }
    if (path === "/api/login") return response({ok:true},200,origin);
    if (path !== "/api/publish") return response({ok:false,error:"Not found"},404,origin);
    if (!validConfig(body.config)) return response({ok:false,error:"配置格式错误或包含不支持的链接"},400,origin);
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPO || "")) return response({ok:false,error:"GITHUB_REPO 未正确设置"},500,origin);
    const api = `https://api.github.com/repos/${env.GITHUB_REPO}/contents/config.js`;
    const headers = {
      "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "XY-Space-Station-Worker"
    };
    try {
      const current = await fetch(api, {headers});
      let sha;
      if (current.ok) sha = (await current.json()).sha;
      else if (current.status !== 404) {
        const error = await current.json().catch(()=>({}));
        return response({ok:false,error:error.message || "无法读取 GitHub 配置文件"},502,origin);
      }
      const source = "window.SITE_CONFIG = " + JSON.stringify(body.config, null, 4) + ";\n";
      const bytes = new TextEncoder().encode(source);
      let binary = "";
      for (let i=0;i<bytes.length;i+=0x8000) binary += String.fromCharCode(...bytes.subarray(i,i+0x8000));
      const put = await fetch(api, {
        method:"PUT",
        headers:{...headers,"Content-Type":"application/json"},
        body:JSON.stringify({
          message:"site: update personal space config",
          content:btoa(binary),
          ...(sha ? {sha} : {})
        })
      });
      if (!put.ok) {
        const error = await put.json().catch(()=>({}));
        return response({ok:false,error:error.message || "GitHub 发布失败，请检查 Token 权限和仓库路径"},502,origin);
      }
      return response({ok:true,message:"Configuration published"},200,origin);
    } catch (e) {
      return response({ok:false,error:"GitHub 网络请求失败"},502,origin);
    }
  }
};
