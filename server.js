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

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const JWT_SECRET = process.env.JWT_SECRET || 'ahurus-secret-2025';

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token inválido' }); }
}

function admin(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'Acceso denegado' });
  next();
}

// ─── REGISTER ────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { nombre, email, password } = req.body;
    if (!nombre || !email || !password) return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    const { data: ex } = await supabase.from('usuarios').select('id').eq('email', email).maybeSingle();
    if (ex) return res.status(400).json({ error: 'Ya existe una cuenta con ese email' });
    const hash = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from('usuarios').insert([{ nombre, email, password_hash: hash, es_admin: false }]).select().single();
    if (error) return res.status(500).json({ error: 'Error al crear la cuenta: ' + error.message });
    const token = jwt.sign({ id: data.id, email: data.email, nombre: data.nombre, isAdmin: false }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, usuario: { id: data.id, nombre: data.nombre, email: data.email, isAdmin: false } });
  } catch(e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Error interno del servidor: ' + e.message });
  }
});

// ─── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email y contraseña son obligatorios' });
    const { data: user } = await supabase.from('usuarios').select('*').eq('email', email).maybeSingle();
    if (!user) return res.status(400).json({ error: 'Email o contraseña incorrectos' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'Email o contraseña incorrectos' });
    const token = jwt.sign({ id: user.id, email: user.email, nombre: user.nombre, isAdmin: user.es_admin }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, usuario: { id: user.id, nombre: user.nombre, email: user.email, isAdmin: user.es_admin } });
  } catch(e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Error interno del servidor: ' + e.message });
  }
});

// ─── GENERATE REPORT ─────────────────────────────────────────────────────────
app.post('/api/generar-informe', auth, async (req, res) => {
  try {
    const { expenseData } = req.body;
    if (!expenseData) return res.status(400).json({ error: 'Faltan datos' });

    let result;
    try {
      console.log('Llamando a Anthropic API...');
      console.log('API Key configurada:', process.env.ANTHROPIC_API_KEY ? 'SI (empieza por ' + process.env.ANTHROPIC_API_KEY.substring(0,10) + '...)' : 'NO');
      const message = await anthropic.messages.create({
        model: 'claude-sonnet-4-5',
        max_tokens: 4000,
        messages: [{ role: 'user', content: buildPrompt(expenseData) }]
      });
      console.log('Respuesta de Anthropic recibida correctamente');
      let text = message.content[0].text.replace(/```json/g,'').replace(/```html/g,'').replace(/```/g,'').trim();
      // Clean literal \n characters that AI sometimes outputs as text
      text = text.replace(/\\n/g, '').replace(/\n\n/g, '').replace(/^\s*\n/gm, '');
      result = parseAIResponse(text, expenseData);
    } catch (e) {
      console.error('ERROR en Anthropic API:', e.message);
      console.error('Tipo de error:', e.constructor.name);
      result = generateLocalReport(expenseData);
    }

    const resumen = result.html_content.replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim().substring(0,300);
    const { data: informe, error } = await supabase.from('informes').insert([{
      usuario_id: req.user.id,
      respuestas: expenseData,
      html_informe: result.html_content,
      resumen,
      ahorro_estimado: result.ahorroEstimado || 0,
      gasto_total: result.totalDeclarado || 0,
      comparativa_data: result.comparativa || null
    }]).select().single();

    if (error) {
      console.error('Error guardando en Supabase:', error.message);
      return res.status(500).json({ error: 'Error al guardar el informe: ' + error.message });
    }

    res.json({
      informe_data: {
        totalDeclarado: result.totalDeclarado,
        ahorroEstimado: result.ahorroEstimado,
        comparativa: result.comparativa
      },
      html_content: result.html_content,
      id: informe.id
    });
  } catch(e) {
    console.error('ERROR GENERAL en generar-informe:', e.message);
    res.status(500).json({ error: 'Error interno: ' + e.message });
  }
});

// ─── HISTORIAL ────────────────────────────────────────────────────────────────
app.get('/api/mis-informes', auth, async (req, res) => {
  const { data } = await supabase.from('informes').select('id, created_at, resumen, ahorro_estimado, gasto_total').eq('usuario_id', req.user.id).order('created_at', { ascending: false });
  res.json(data || []);
});

app.get('/api/informe/:id', auth, async (req, res) => {
  const { data } = await supabase.from('informes').select('*').eq('id', req.params.id).eq('usuario_id', req.user.id).single();
  if (!data) return res.status(404).json({ error: 'Informe no encontrado' });
  res.json(data);
});

// ─── ADMIN ────────────────────────────────────────────────────────────────────
app.get('/api/admin/usuarios', auth, admin, async (req, res) => {
  const { data } = await supabase.from('usuarios').select('id, nombre, email, es_admin, created_at').order('created_at', { ascending: false });
  res.json(data || []);
});

app.get('/api/admin/estadisticas', auth, admin, async (req, res) => {
  const { count: totalUsuarios } = await supabase.from('usuarios').select('*', { count: 'exact', head: true });
  const { count: totalInformes } = await supabase.from('informes').select('*', { count: 'exact', head: true });
  const { data: ultimosInformes } = await supabase.from('informes').select('id, created_at, resumen, ahorro_estimado, gasto_total, usuarios(nombre, email)').order('created_at', { ascending: false }).limit(10);
  res.json({ totalUsuarios, totalInformes, ultimosInformes: ultimosInformes || [] });
});

app.get('/api/admin/usuario/:id/informes', auth, admin, async (req, res) => {
  const { data } = await supabase.from('informes').select('id, created_at, resumen, ahorro_estimado, gasto_total, html_informe').eq('usuario_id', req.params.id).order('created_at', { ascending: false });
  res.json(data || []);
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ─── BUILD PROMPT ─────────────────────────────────────────────────────────────
function buildPrompt(data) {
  const { profile, gastos, gastosNoSe, totalDeclarado } = data;

  const gastosTexto = Object.entries(gastos).map(([catId, cat]) => {
    const partidas = Object.entries(cat.partidas || {}).map(([k, v]) =>
      `  - ${v.label}: ${v.valor === 'estimar' ? 'A ESTIMAR por IA' : v.valor+'€'}`
    ).join('\n');
    return `${cat.emoji} ${cat.nombre} (total declarado: ${cat.total||0}€):\n${partidas}`;
  }).join('\n\n');

  return `Eres un asesor financiero experto en economía doméstica española con profundo conocimiento de las estadísticas de gasto por comunidad autónoma del INE 2024-2025.

PERFIL DEL USUARIO:
- Comunidad autónoma: ${profile.comunidad}
- Tipo de municipio: ${profile.tamano}
- Composición familiar: ${profile.familia}, ${profile.personas} personas
- Situación de vivienda: ${profile.vivienda}
- Ingresos netos mensuales: ${profile.ingresos}
- Total gasto declarado: ${totalDeclarado}€/mes

GASTOS REALES DECLARADOS:
${gastosTexto}

${gastosNoSe?.length ? `PARTIDAS A ESTIMAR (el usuario no sabe el importe exacto):\n${gastosNoSe.map(g=>`- ${g.cat}: ${g.sub}`).join('\n')}` : ''}

TU TAREA:
Genera un análisis completo y muy personalizado en formato JSON con esta estructura exacta:

{
  "comparativa": [
    {
      "categoria": "Vivienda",
      "emoji": "🏠",
      "tuyo": 1200,
      "estandar": 950,
      "comentario": "Estás pagando un 26% más que la media en ${profile.comunidad} para una familia como la tuya"
    }
  ],
  "totalDeclarado": ${totalDeclarado},
  "totalConEstimados": 2800,
  "ahorroEstimado": 320,
  "html": "...HTML del informe..."
}

INSTRUCCIONES PARA LA COMPARATIVA:
1. Para CADA categoría de gasto, calcula el "estandar" realista para:
   - Una familia de tipo "${profile.familia}" (${profile.personas} personas)
   - En ${profile.comunidad}, municipio tipo "${profile.tamano}"
   - Con ingresos de "${profile.ingresos}"
   - Usa datos reales del INE, Eurostat y estudios de consumo españoles 2024
2. Para las partidas marcadas "A ESTIMAR", calcula un valor realista y súmalo al totalConEstimados
3. El semáforo es: rojo si supera +15% la media, verde si está -15% por debajo, amarillo si está en la media

INSTRUCCIONES PARA EL HTML:
El HTML debe ser MUY VISUAL y PERSONAL. Estructura obligatoria:

<div class="saving-hero"><div class="sh-label">Puedes ahorrar cada mes</div><div class="sh-amount">TOTAL€</div><div class="sh-sub">aplicando las recomendaciones de tu informe</div></div>

<h3>🔍 Lo que hemos descubierto sobre tus gastos</h3>
<p>Párrafo introductorio MUY PERSONAL que mencione específicamente: la comunidad, el tipo de familia, los gastos donde más se desvía. Que el usuario sienta que es solo para él/ella.</p>

<h3>🚨 Donde más puedes mejorar</h3>
Para CADA categoría donde el usuario supere la media en más de un 15%, genera una tarjeta así:
<div class="opp-card">
  <div class="opp-card-top">
    <div class="opp-num">1</div>
    <div><div class="opp-title">CATEGORIA — Gastas X€ más que la media</div><span class="opp-saving">Potencial: XX€/mes</span></div>
  </div>
  <div class="opp-body">Explicación muy específica: por qué gasta más, qué puede cambiar exactamente (nombres reales de supermercados, operadoras, comparadores en ${profile.comunidad}), cuánto puede ahorrar. Muy concreto y accionable.</div>
</div>

<h3>✅ Lo que estás haciendo bien</h3>
<div class="congrat-box">Lista de las categorías donde el usuario está por debajo de la media. Que se sienta reconocido y motivado. Personaliza mencionando los importes concretos.</div>

<h3>📋 Tu plan de acción — primeros pasos</h3>
Genera 3 pasos MUY CONCRETOS ordenados por impacto:
<div class="step-card"><div class="step-num">1</div><div class="step-body"><div class="step-title">Acción concreta esta semana</div><div class="step-desc">Instrucción específica con nombres reales de apps, webs, servicios para ${profile.comunidad}. Tiempo estimado y ahorro esperado.</div></div></div>

<h3>💡 Gastos invisibles detectados en tu perfil</h3>
<p>Basándote en su perfil específico (${profile.familia}, ${profile.tamano} en ${profile.comunidad}), identifica 4-5 gastos invisibles típicos CON ESTIMACIÓN EN EUROS de cuánto pueden sumarle al mes sin que se dé cuenta.</p>

REGLAS CRÍTICAS:
- NUNCA uses \n, \n\n ni saltos de línea literales en el HTML — usa solo etiquetas HTML
- Si el perfil es "persona sola", usa SIEMPRE "tú" y habla de UNA sola persona. NUNCA digas "vosotros", "pareja" ni "dos personas"
- Si es familia, usa "vosotros" y menciona el número exacto de personas (${profile.personas})
- Gastos invisibles: sé REALISTA. Para una persona sola, el café puede ser 20-30€/mes, no 160€. Para familia de 4, máximo 60-80€ en cafés. No multipliques por personas de forma mecánica
- Calibra TODO para ${profile.comunidad} con datos reales
- El ahorro potencial debe ser realista y alcanzable, no exagerado
- Solo HTML limpio dentro del campo "html", absolutamente sin \n ni \n\n ni markdown`;
}

// ─── PARSE AI RESPONSE ────────────────────────────────────────────────────────
function cleanHtml(html) {
  if (!html) return '';
  // Remove literal \n characters that AI sometimes outputs
  return html
    .replace(/\\n/g, ' ')
    .replace(/\n/g, ' ')
    .replace(/\t/g, ' ')
    .replace(/  +/g, ' ')
    .trim();
}

function parseAIResponse(text, expenseData) {
  try {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON found');
    const parsed = JSON.parse(jsonMatch[0]);
    return {
      comparativa: parsed.comparativa || [],
      totalDeclarado: parsed.totalDeclarado || expenseData.totalDeclarado || 0,
      ahorroEstimado: parsed.ahorroEstimado || 0,
      html_content: cleanHtml(parsed.html || parsed.html_content || generateLocalReport(expenseData).html_content)
    };
  } catch(e) {
    const htmlMatch = text.match(/<[\s\S]*>/);
    return {
      comparativa: [],
      totalDeclarado: expenseData.totalDeclarado || 0,
      ahorroEstimado: 0,
      html_content: cleanHtml(htmlMatch ? htmlMatch[0] : text)
    };
  }
}

// ─── LOCAL REPORT (sin API key) ───────────────────────────────────────────────
function generateLocalReport(data) {
  const { profile, gastos, totalDeclarado } = data;
  const personas = parseInt(profile.personas) || 2;
  const comunidad = profile.comunidad || 'tu comunidad';
  const ingresos = profile.ingresos || 'entre 2.500€ y 4.000€';
  const ingresosNum = ingresos.includes('6.000') ? 7000 : ingresos.includes('4.000') ? 5000 : ingresos.includes('2.500') ? 3200 : ingresos.includes('1.500') ? 2000 : 1200;
  const esFamilia = profile.familia && !profile.familia.includes('solo') && !profile.familia.includes('pareja');
  const pronombre = profile.familia?.includes('solo') ? 'tú' : 'vosotros';
  const esCiudadGrande = profile.tamano?.includes('gran ciudad');
  const multiplicadorZona = esCiudadGrande ? 1.25 : profile.tamano?.includes('mediana') ? 1.0 : 0.85;

  // Estándares por categoría ajustados por zona y familia
  const estandares = {
    vivienda: Math.round(750 * multiplicadorZona * (personas > 2 ? 1.1 : 1)),
    alimentacion: Math.round(200 * personas * (esCiudadGrande ? 1.1 : 0.95)),
    transporte: Math.round(180 * (personas > 2 ? 1.3 : 1) * multiplicadorZona),
    seguros: Math.round(120 * personas * 0.6),
    educacion: esFamilia ? Math.round(150 * (personas - 2)) : 0,
    ropa: Math.round(80 * personas),
    salud: Math.round(40 * personas),
    ocio: Math.round(150 * (personas > 2 ? 1.5 : 1) * (esCiudadGrande ? 1.2 : 0.9)),
    hogar: Math.round(90 * (personas > 2 ? 1.2 : 1)),
  };

  // Calcular totales por categoría
  const totalesPorCat = {};
  const catEmojis = { vivienda:'🏠', alimentacion:'🛒', transporte:'🚗', seguros:'🛡️', educacion:'📚', ropa:'👕', salud:'💊', ocio:'🎬', hogar:'🧴' };

  Object.entries(gastos).forEach(([catId, cat]) => {
    totalesPorCat[catId] = cat.total || 0;
  });

  // Generar comparativa
  const comparativa = Object.entries(estandares).map(([catId, estandar]) => {
    const tuyo = totalesPorCat[catId] || 0;
    const catNombres = { vivienda:'Vivienda', alimentacion:'Alimentación', transporte:'Transporte', seguros:'Seguros', educacion:'Educación', ropa:'Ropa y calzado', salud:'Salud', ocio:'Ocio', hogar:'Cuidado personal' };
    if(tuyo === 0 && estandar === 0) return null;
    return { categoria: catNombres[catId] || catId, emoji: catEmojis[catId]||'💶', tuyo, estandar };
  }).filter(Boolean);

  // Calcular ahorro potencial
  const ahorroEstimado = Math.round(comparativa.reduce((sum, c) => {
    const exceso = (c.tuyo || 0) - (c.estandar || 0);
    return sum + (exceso > 0 ? exceso * 0.6 : 0);
  }, 0));

  // Identificar dónde se pasa
  const excesos = comparativa.filter(c => c.tuyo > c.estandar * 1.15).sort((a,b) => (b.tuyo-b.estandar)-(a.tuyo-a.estandar));
  const ahorros = comparativa.filter(c => c.tuyo <= c.estandar * 0.85 && c.tuyo > 0);

  // Recomendaciones por comunidad
  const recomendaciones = {
    supermercado: comunidad === 'Madrid' || comunidad === 'Cataluña' ? 'Mercadona, Lidl o Aldi' :
                  comunidad === 'País Vasco' ? 'Eroski, Lidl o Aldi' :
                  comunidad === 'Galicia' ? 'Gadis, Lidl o Mercadona' :
                  comunidad === 'Andalucía' ? 'Mercadona, Lidl o Aldi' : 'Lidl, Aldi o Mercadona',
    operadora: 'Digi (desde 22€/mes fibra + móvil), Pepephone o Simyo',
    comparador: 'comparador.cnmc.es para la luz, Acierto.com para seguros',
  };

  const html = `
<div class="saving-hero">
  <div class="sh-label">Puedes ahorrar cada mes</div>
  <div class="sh-amount">${ahorroEstimado > 0 ? ahorroEstimado+'€' : 'Ver análisis'}</div>
  <div class="sh-sub">aplicando las recomendaciones de tu informe personalizado</div>
</div>

<h3>🔍 Lo que hemos descubierto sobre tus gastos</h3>
<p>Hemos analizado detalladamente los gastos de ${pronombre === 'tú' ? 'tu hogar' : 'vuestra familia de '+personas+' personas'} en ${comunidad}. Tu gasto total declarado es de <strong>${(totalDeclarado||0).toLocaleString('es-ES')}€/mes</strong>, y lo hemos comparado con familias similares a la tuya en ${comunidad}. ${excesos.length > 0 ? `Hemos encontrado <strong>${excesos.length} categorías</strong> donde gastas más de lo habitual para tu perfil, con un potencial de ahorro de hasta <strong>${ahorroEstimado}€ al mes</strong>.` : 'En general tu gestión económica es buena, aunque siempre hay margen de mejora.'}</p>

${excesos.length > 0 ? `<h3>🚨 Donde más puedes mejorar</h3>
${excesos.slice(0,4).map((c, i) => {
  const exceso = c.tuyo - c.estandar;
  const ahorroPotencial = Math.round(exceso * 0.6);
  let consejo = '';
  if(c.categoria === 'Alimentación') consejo = `Concentra el 70% de la compra en ${recomendaciones.supermercado}. Una familia como la tuya en ${comunidad} puede reducir este gasto hasta un 20% sin cambiar su dieta.`;
  else if(c.categoria === 'Vivienda') consejo = `Revisa tu tarifa de luz en ${recomendaciones.comparador}. La tarifa con horas valle puede ahorrarte entre 15€ y 30€ al mes programando electrodomésticos de noche.`;
  else if(c.categoria === 'Transporte') consejo = `Con ${c.tuyo}€/mes en transporte, estás un ${Math.round(exceso/c.estandar*100)}% sobre la media en ${comunidad}. Revisa si puedes combinar con transporte público o compartir desplazamientos.`;
  else if(c.categoria === 'Seguros') consejo = `Compara tus seguros en Acierto.com o Rastreator.com. Las familias que comparan ahorran de media entre 200€ y 400€ al año sin perder coberturas.`;
  else if(c.categoria === 'Ocio') consejo = `Revisa tus suscripciones activas — muchas familias pagan por servicios que apenas usan. Rotar entre plataformas de streaming en lugar de tenerlas todas activas puede ahorrarte 20-30€/mes.`;
  else if(c.categoria === 'Ropa y calzado') consejo = `Planificar las compras de ropa en temporada de rebajas y usar apps como Vinted para ropa de calidad a menos precio puede reducir este gasto considerablemente.`;
  else consejo = `Este gasto está por encima de la media para tu perfil en ${comunidad}. Revisarlo con detalle puede revelarte oportunidades de ahorro importantes.`;
  return `<div class="opp-card">
    <div class="opp-card-top">
      <div class="opp-num">${i+1}</div>
      <div><div class="opp-title">${c.emoji} ${c.categoria} — Gastas ${exceso.toLocaleString('es-ES')}€ más que la media</div><span class="opp-saving">Potencial: ${ahorroPotencial}€/mes</span></div>
    </div>
    <div class="opp-body">${consejo} Tu gasto actual: <strong>${c.tuyo}€/mes</strong> vs. media similar en ${comunidad}: <strong>${c.estandar}€/mes</strong>.</div>
  </div>`;
}).join('')}` : ''}

${ahorros.length > 0 ? `<h3>✅ Lo que estás haciendo bien</h3>
<div class="congrat-box">
  <strong>¡Enhorabuena!</strong> En estas categorías gastas por debajo de la media de familias similares en ${comunidad}:<br><br>
  ${ahorros.map(c => `<strong>${c.emoji} ${c.categoria}:</strong> ${c.tuyo}€ vs. ${c.estandar}€ de media (ahorras ${c.estandar - c.tuyo}€/mes más que la media)`).join('<br>')}
</div>` : ''}

<h3>📋 Tu plan de acción — primeros pasos</h3>
<div class="step-card"><div class="step-num">1</div><div class="step-body"><div class="step-title">Esta semana — Revisa tus suscripciones y seguros</div><div class="step-desc">Abre el extracto de tu banco del último mes. Busca todos los cargos recurrentes pequeños (Netflix, Spotify, apps...). Cancela los que no usas activamente. Después compara tus seguros en <strong>Acierto.com</strong>. Esta acción sola puede liberarte 50-100€/mes. Tiempo estimado: 30 minutos.</div></div></div>
<div class="step-card"><div class="step-num">2</div><div class="step-body"><div class="step-title">Próxima semana — Optimiza tu compra</div><div class="step-desc">Prueba a hacer la compra principal en <strong>${recomendaciones.supermercado}</strong> durante un mes. Usa la app <strong>Tiendeo</strong> antes de ir para ver las ofertas de la semana. Planifica el menú con antelación y haz una sola compra grande. El ahorro puede ser del 15-20% en este gasto.</div></div></div>
<div class="step-card"><div class="step-num">3</div><div class="step-body"><div class="step-title">Este mes — Revisa tus tarifas de suministros</div><div class="step-desc">Entra en <strong>comparador.cnmc.es</strong> (es gratis y oficial) y comprueba si tu tarifa de luz es la más económica. Activa la tarifa con discriminación horaria si no la tienes. Llama al número de bajas de tu operadora de internet y móvil y pide mejora de tarifa o cámbiate a <strong>${recomendaciones.operadora}</strong>.</div></div></div>

<h3>💡 Gastos invisibles en tu perfil</h3>
<p>Basándonos en ${pronombre === 'tú' ? 'tu perfil' : 'vuestro perfil'} de ${profile.familia} en ${comunidad}, estos son los gastos que probablemente no estás contabilizando pero que suman cada mes:</p>
<ul>
  <li><strong>Cafés y consumiciones rápidas:</strong> ${personas} personas × ~40€/mes = ${personas*40}€/mes que "desaparecen" sin sentir</li>
  <li><strong>Compras impulsivas online:</strong> Amazon, Zara online, apps... entre 50€ y 100€/mes de media</li>
  <li><strong>Farmacia sin receta:</strong> Vitaminas, complementos, parafarmacia sin receta: 20-40€/mes</li>
  <li><strong>Regalos y celebraciones:</strong> Cumpleaños, cenas de empresa, regalos varios prorrateados: 30-60€/mes</li>
  ${esFamilia ? '<li><strong>Material escolar fuera de temporada:</strong> Fotocopias, material extra, excursiones: 20-40€/mes</li>' : ''}
  <li><strong>Suscripciones olvidadas:</strong> Apps, servicios digitales que ya no usas: 15-30€/mes</li>
</ul>
<p>En total, estos gastos invisibles pueden sumar entre <strong>${personas*40+80}€ y ${personas*50+130}€ al mes</strong> sin que ${pronombre === 'tú' ? 'te des cuenta' : 'os deis cuenta'}.</p>`;

  return { comparativa, totalDeclarado, ahorroEstimado, html_content: html };
}

// ─── START SERVER ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Ahurus server corriendo en puerto ${PORT}`));
