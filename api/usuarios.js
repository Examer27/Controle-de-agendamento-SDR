// Função da Vercel: cria, desativa/reativa e troca a senha de usuários.
// Só funciona para quem está logado como administrador.
// Variáveis de ambiente (Vercel > Settings > Environment Variables):
//   SUPABASE_URL          = https://SEU-PROJETO.supabase.co
//   SUPABASE_SECRET_KEY   = chave "Secret key" do Supabase (nunca colocar no HTML)
//   DOMINIO_EMAIL         = (opcional) ex.: @suaempresa.com.br  -> só aceita e-mails desse domínio
const { createClient } = require("@supabase/supabase-js");

const PERFIS = ["admin", "sdr", "gerente"];
const resp = (res, code, obj) => res.status(code).json(obj);

module.exports = async (req, res) => {
  if (req.method !== "POST") return resp(res, 405, { ok: false, erro: "Método não permitido" });
  const url = process.env.SUPABASE_URL, key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return resp(res, 500, { ok: false, erro: "Servidor sem configuração (variáveis de ambiente)" });
  const sb = createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    const { data: u } = await sb.auth.getUser(token);
    if (!u || !u.user) return resp(res, 401, { ok: false, erro: "Sessão inválida" });
    const { data: me } = await sb.from("perfis").select("perfil,ativo").eq("user_id", u.user.id).maybeSingle();
    if (!me || !me.ativo || me.perfil !== "admin") return resp(res, 403, { ok: false, erro: "Apenas administradores" });

    const b = typeof req.body === "string" ? JSON.parse(req.body) : (req.body || {});
    const id = String(b.user_id || "");

    if (b.acao === "criar") {
      const email = String(b.email || "").trim().toLowerCase();
      const nome = String(b.nome || "").trim().slice(0, 80);
      const senha = String(b.senha || "");
      if (!nome || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return resp(res, 400, { ok: false, erro: "Informe nome e e-mail válidos" });
      if (!PERFIS.includes(b.perfil)) return resp(res, 400, { ok: false, erro: "Perfil inválido" });
      if (senha.length < 8) return resp(res, 400, { ok: false, erro: "A senha precisa ter pelo menos 8 caracteres" });
      const dom = (process.env.DOMINIO_EMAIL || "").trim().toLowerCase();
      if (dom && !email.endsWith(dom)) return resp(res, 400, { ok: false, erro: "Use o e-mail corporativo (" + dom + ")" });
      if (b.perfil !== "admin") {
        const lista = b.perfil === "gerente" ? "gerentes" : "sdrs";
        const cd = await sb.from("docs").select("path").eq("collection", "cadastros").eq("data->>lista", lista).eq("data->>nome", nome).limit(1);
        if (cd.error || !cd.data || !cd.data.length) return resp(res, 400, { ok: false, erro: "Cadastre esse nome em Cadastros antes de criar o acesso" });
      }
      const c = await sb.auth.admin.createUser({ email, password: senha, email_confirm: true });
      if (c.error) return resp(res, 400, { ok: false, erro: /already|registered/i.test(c.error.message) ? "Este e-mail já está cadastrado" : c.error.message });
      const ins = await sb.from("perfis").insert({ user_id: c.data.user.id, email, nome, perfil: b.perfil });
      if (ins.error) { await sb.auth.admin.deleteUser(c.data.user.id); return resp(res, 400, { ok: false, erro: ins.error.message }); }
      return resp(res, 200, { ok: true });
    }

    if (!id) return resp(res, 400, { ok: false, erro: "Usuário não informado" });

    if (b.acao === "senha") {
      const senha = String(b.senha || "");
      if (senha.length < 8) return resp(res, 400, { ok: false, erro: "A senha precisa ter pelo menos 8 caracteres" });
      const r = await sb.auth.admin.updateUserById(id, { password: senha });
      if (r.error) return resp(res, 400, { ok: false, erro: r.error.message });
      return resp(res, 200, { ok: true });
    }

    if (b.acao === "desativar" || b.acao === "reativar") {
      const des = b.acao === "desativar";
      if (des && id === u.user.id) return resp(res, 400, { ok: false, erro: "Você não pode desativar a própria conta" });
      const up = await sb.from("perfis").update({ ativo: !des }).eq("user_id", id);
      if (up.error) return resp(res, 400, { ok: false, erro: up.error.message });
      const r = await sb.auth.admin.updateUserById(id, { ban_duration: des ? "876000h" : "none" });
      if (r.error) return resp(res, 400, { ok: false, erro: r.error.message });
      return resp(res, 200, { ok: true });
    }

    return resp(res, 400, { ok: false, erro: "Ação desconhecida" });
  } catch (e) {
    return resp(res, 500, { ok: false, erro: "Erro no servidor" });
  }
};
