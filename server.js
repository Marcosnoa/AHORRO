require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Anthropic = require('@anthropic-ai/sdk');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const JWT_SECRET = process.env.JWT_SECRET || 'ahorri-secret-2025';

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'Acceso denegado' });
  next();
}

app.post('/api/register', async (req, res) => {
  const { nombre, email, password } = req.body;
  if (!nombre || !email || !password)
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  const { data: existing } = await supabase.from('usuarios').select('id').eq('email', email).single();
  if (existing) return res.status(400).json({ error: 'Ya existe una cuenta con ese email' });
  const passwordHash = await bcrypt.hash(password, 10);
  const { data, error } = await supabase.from('usuarios').insert([{ nombre, email, password_hash: passwordHash, es_admin: false }]).select().single();
  if (error) return res.status(500).json({ error: 'Error al crear la cuenta' });
  const token = jwt.sign({ id: data.id, email: data.email, nombre: data.nombre, isAdmin: false }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, usuario: { id: data.id, nombre: data.nombre, email: data.email, isAdmin: false } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const { data: user } = await supabase.from('usuarios').select('*').eq('email', email).single();
  if (!user) return res.status(400).json({ error: 'Email o contraseña incorrectos' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: 'Email o contraseña incorrectos' });
  const token = jwt.sign({ id: user.id, email: user.email, nombre: user.nombre, isAdmin: user.es_admin }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, usuario: { id: user.id, nombre: user.nombre, email: user.email, isAdmin: user.es_admin } });
});

app.get('/api/perfil', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('usuarios').select('id, nombre, email, es_admin, created_at').eq('id', req.user.id).single();
  res.json(data);
});

app.post('/api/generar-informe', authMiddleware, async (req, res) => {
  const { respuestas } = req.body;
  if (!respuestas) return res.status(400).json({ error: 'Faltan datos' });
  let htmlInforme = '';
  try {
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 3000,
      messages: [{ role: 'user', content: buildPrompt(respuestas) }]
    });
    htmlInforme = message.content[0].text.replace(/```html/g, '').replace(/```/g, '').trim();
  } catch (aiError) {
    htmlInforme = generarInformeLocal(respuestas);
  }
  const resumenTexto = htmlInforme.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().substring(0, 300);
  const { data: informe, error } = await supabase.from('informes').insert([{
    usuario_id: req.user.id,
    respuestas: respuestas,
    html_informe: htmlInforme,
    resumen: resumenTexto,
    ahorro_estimado: extraerAhorro(htmlInforme)
  }]).select().single();
  if (error) return res.status(500).json({ error: 'Error al guardar el informe' });
  res.json({ informe: htmlInforme, id: informe.id });
});

app.get('/api/mis-informes', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('informes').select('id, created_at, resumen, ahorro_estimado, respuestas').eq('usuario_id', req.user.id).order('created_at', { ascending: false });
  res.json(data || []);
});

app.get('/api/informe/:id', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('informes').select('*').eq('id', req.params.id).eq('usuario_id', req.user.id).single();
  if (!data) return res.status(404).json({ error: 'Informe no encontrado' });
  res.json(data);
});

app.get('/api/admin/usuarios', authMiddleware, adminMiddleware, async (req, res) => {
  const { data } = await supabase.from('usuarios').select('id, nombre, email, es_admin, created_at').order('created_at', { ascending: false });
  res.json(data || []);
});

app.get('/api/admin/estadisticas', authMiddleware, adminMiddleware, async (req, res) => {
  const { count: totalUsuarios } = await supabase.from('usuarios').select('*', { count: 'exact', head: true });
  const { count: totalInformes } = await supabase.from('informes').select('*', { count: 'exact', head: true });
  const { data: ultimosInformes } = await supabase.from('informes').select('id, created_at, resumen, ahorro_estimado, usuarios(nombre, email)').order('created_at', { ascending: false }).limit(10);
  res.json({ totalUsuarios, totalInformes, ultimosInformes: ultimosInformes || [] });
});

app.get('/api/admin/usuario/:id/informes', authMiddleware, adminMiddleware, async (req, res) => {
  const { data } = await supabase.from('informes').select('id, created_at, resumen, ahorro_estimado, respuestas, html_informe').eq('usuario_id', req.params.id).order('created_at', { ascending: false });
  res.json(data || []);
});

app.patch('/api/admin/usuario/:id/admin', authMiddleware, adminMiddleware, async (req, res) => {
  const { es_admin } = req.body;
  await supabase.from('usuarios').update({ es_admin }).eq('id', req.params.id);
  res.json({ ok: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

function buildPrompt(r) {
  return `Eres un asesor financiero experto en economía doméstica española. Genera un informe de ahorro personalizado en HTML limpio (solo h3, h4, p, ul, li, strong, div con clases específicas).

DATOS: Comunidad: ${r.comunidad} (${r.tamanoMunicipio}), Familia: ${r.familia}, ${r.personas} personas, Vivienda: ${r.tipoVivienda} ${r.situacionVivienda} ${r.metrosVivienda}m², Energía: ${r.sistemaEnergetico}, Estilo vida: ${r.estiloVida}, Transporte: ${r.transporte} distancia ${r.distanciaTrabajo}, Supermercados: ${r.supermercados}, Come fuera: ${r.comerFuera}, Ingresos: ${r.ingresos}.

Genera un informe único y personalizado con:
1. <div class="intro-personal">Introducción muy personal para ESTA familia</div>
2. Para cada categoría de gasto: <div class="gasto-categoria" data-categoria="NOMBRE" data-importe="NUMERO"><h4>icono Nombre</h4><p>explicación específica</p><div class="gasto-desglose">desglose en euros</div></div>
Categorías: Aseo e higiene, Alimentación, Energía, Transporte, Ocio, Hogar, Comunicaciones, Gastos invisibles, Ropa, Otros.
3. <h3>Oportunidades de ahorro</h3> con <div class="oportunidad-ahorro" data-ahorro="NUMERO"> para cada una, con nombres reales españoles (Lidl, Digi, Fintonic...).
4. <div class="gastos-invisibles">gastos invisibles específicos con estimación</div>
5. <ul class="plan-accion">3 pasos concretos esta semana</ul>
6. <div class="resumen-ahorro" data-total-ahorro="NUMERO">resumen final con ahorro total mensual y anual</div>
Tono cercano y motivador. Solo HTML limpio.`;
}

function generarInformeLocal(r) {
  const personas = parseInt(r.personas) || 3;
  const baseAlimentacion = personas * 180;
  const baseEnergia = r.sistemaEnergetico?.includes('gas') ? 80 : 110;
  const baseTransporte = r.transporte?.includes('coche') ? 180 : 60;
  const totalEstimado = baseAlimentacion + baseEnergia + baseTransporte + 200;
  const ahorroEstimado = Math.round(totalEstimado * 0.22);
  return `<div class="intro-personal">Hemos analizado la situación de vuestra familia de <strong>${personas} personas</strong> en <strong>${r.comunidad}</strong>. Con un estilo de vida <strong>${r.estiloVida}</strong> y usando <strong>${r.sistemaEnergetico}</strong>, estimamos un gasto mensual total de <strong>${totalEstimado}€</strong> y un potencial de ahorro de <strong>${ahorroEstimado}€/mes</strong>.</div>
<h3>📊 Desglose de vuestro gasto mensual</h3>
<div class="gasto-categoria" data-categoria="Aseo e higiene" data-importe="${personas*18}"><h4>🚿 Aseo e higiene</h4><p>Para ${personas} personas con ${r.sistemaEnergetico}, cada ducha diaria supone unos 0,35€ por persona.</p><div class="gasto-desglose">Agua caliente (${personas*10}€) · Productos higiene (${personas*5}€) · Otros (${personas*3}€)</div></div>
<div class="gasto-categoria" data-categoria="Alimentación" data-importe="${baseAlimentacion}"><h4>🛒 Alimentación</h4><p>Comprando en ${r.supermercados} y comiendo fuera ${r.comerFuera}, la alimentación de ${personas} personas supone el mayor gasto.</p><div class="gasto-desglose">Compra (${Math.round(baseAlimentacion*0.75)}€) · Restaurantes (${Math.round(baseAlimentacion*0.15)}€) · Extras (${Math.round(baseAlimentacion*0.10)}€)</div></div>
<div class="gasto-categoria" data-categoria="Energía" data-importe="${baseEnergia}"><h4>⚡ Energía</h4><p>Con ${r.sistemaEnergetico} en ${r.metrosVivienda}m² en ${r.comunidad}.</p><div class="gasto-desglose">Calefacción (${Math.round(baseEnergia*0.4)}€) · Agua caliente (${Math.round(baseEnergia*0.25)}€) · Electrodomésticos (${Math.round(baseEnergia*0.35)}€)</div></div>
<div class="gasto-categoria" data-categoria="Transporte" data-importe="${baseTransporte}"><h4>🚗 Transporte</h4><p>Con ${r.transporte} y distancia de ${r.distanciaTrabajo}.</p><div class="gasto-desglose">Combustible/bonos (${Math.round(baseTransporte*0.65)}€) · Mantenimiento (${Math.round(baseTransporte*0.35)}€)</div></div>
<div class="gasto-categoria" data-categoria="Ocio" data-importe="120"><h4>🎬 Ocio</h4><p>Con estilo de vida ${r.estiloVida}.</p><div class="gasto-desglose">Plataformas (25€) · Salidas (55€) · Otros (40€)</div></div>
<div class="gasto-categoria" data-categoria="Comunicaciones" data-importe="80"><h4>📱 Comunicaciones</h4><p>Internet y móviles en ${r.comunidad}.</p><div class="gasto-desglose">Fibra (35€) · Móviles (45€)</div></div>
<div class="gasto-categoria" data-categoria="Gastos invisibles" data-importe="150"><h4>👻 Gastos invisibles</h4><p>Los que no aparecen en el presupuesto pero suman cada mes.</p><div class="gasto-desglose">Cafés (35€) · Compras impulsivas (45€) · Suscripciones (20€) · Farmacia (30€) · Otros (20€)</div></div>
<h3>🎯 Oportunidades de ahorro</h3>
<div class="oportunidad-ahorro" data-ahorro="${Math.round(baseAlimentacion*0.18)}"><strong>1. Optimizar la compra</strong><p>Concentrad el 70% en <strong>Lidl o Aldi</strong> y usad <strong>Tiendeo</strong> para ver ofertas.</p><div class="ahorro-badge">Ahorro: ${Math.round(baseAlimentacion*0.18)}€/mes</div></div>
<div class="oportunidad-ahorro" data-ahorro="40"><strong>2. Cambiar de operadora</strong><p><strong>Digi</strong> ofrece fibra 1Gb + móvil por 22€/mes.</p><div class="ahorro-badge">Ahorro: 40€/mes</div></div>
<div class="oportunidad-ahorro" data-ahorro="25"><strong>3. Tarifa eléctrica con horas valle</strong><p>Programa electrodomésticos entre 00:00 y 08:00. Compara en <strong>comparador.cnmc.es</strong>.</p><div class="ahorro-badge">Ahorro: 25€/mes</div></div>
<div class="oportunidad-ahorro" data-ahorro="30"><strong>4. Controlar gastos invisibles</strong><p>Usa <strong>Fintonic</strong> para ver todos tus gastos en tiempo real.</p><div class="ahorro-badge">Ahorro: 30€/mes</div></div>
<h3>💡 Gastos del día a día que no veis</h3>
<div class="gastos-invisibles"><ul><li><strong>Cafés:</strong> 2 cafés/día = ~90€/mes por persona</li><li><strong>Suscripciones olvidadas:</strong> 15-30€/mes</li><li><strong>Compras online impulsivas:</strong> 50-80€/mes</li><li><strong>Farmacia de marca:</strong> los genéricos cuestan 3-5 veces menos</li></ul></div>
<h3>📅 Plan de acción esta semana</h3>
<ul class="plan-accion"><li><strong>Hoy:</strong> Descarga <strong>Fintonic</strong> y revisa tus gastos del último mes.</li><li><strong>Esta semana:</strong> Llama al número de bajas de tu operadora y pide mejora de tarifa.</li><li><strong>Este finde:</strong> Planifica el menú semanal y haz una compra única en Lidl.</li></ul>
<div class="resumen-ahorro" data-total-ahorro="${ahorroEstimado}"><p>Podéis ahorrar entre <strong>${ahorroEstimado}€ y ${Math.round(ahorroEstimado*1.4)}€ al mes</strong>, es decir <strong>${ahorroEstimado*12}€ al año</strong>. Con vuestros ingresos de ${r.ingresos} esto supone entre el <strong>8% y el 15% de mejora</strong>.</p></div>`;
}

function extraerAhorro(html) {
  const match = html.match(/data-total-ahorro="(\d+)"/);
  return match ? parseInt(match[1]) : 0;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Ahorri server corriendo en puerto ${PORT}`));
