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

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token inválido' }); }
}

function adminMiddleware(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'Acceso denegado' });
  next();
}

app.post('/api/register', async (req, res) => {
  const { nombre, email, password } = req.body;
  if (!nombre || !email || !password) return res.status(400).json({ error: 'Todos los campos son obligatorios' });
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
      max_tokens: 3500,
      messages: [{ role: 'user', content: buildPrompt(respuestas) }]
    });
    htmlInforme = message.content[0].text.replace(/```html/g, '').replace(/```/g, '').trim();
  } catch (aiError) {
    htmlInforme = generarInformeLocal(respuestas);
  }
  const resumenTexto = htmlInforme.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().substring(0, 300);
  const { data: informe, error } = await supabase.from('informes').insert([{
    usuario_id: req.user.id, respuestas, html_informe: htmlInforme,
    resumen: resumenTexto, ahorro_estimado: extraerAhorro(htmlInforme)
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
  return `Eres un asesor financiero experto en economía doméstica española con acceso a estadísticas del INE, Eurostat y estudios de consumo de hogares españoles. Tu tarea es generar un informe de gasto mensual REALISTA y COMPLETO para esta familia, sin subestimar ninguna partida.

DATOS DE LA FAMILIA:
- Comunidad: ${r.comunidad} (${r.tamano})
- Familia: ${r.familia}, ${r.personas} personas en casa
- Vivienda: ${r.tipoVivienda}, ${r.situacionVivienda}, ${r.metrosVivienda}m²
- Sistema energético: ${r.sistemaEnergetico}
- Seguros contratados: ${r.seguros}
- Educación hijos: ${r.tipoEducacion}. Extras: ${r.extrasEducacion}
- Estilo de vida: ${r.estiloVida}
- Gasto en ropa: ${r.gastoRopa}
- Transporte: ${r.transporte}, distancia al trabajo: ${r.distanciaTrabajo}
- Supermercados: ${r.supermercados}. Come fuera: ${r.comerFuera}
- Ingresos netos: ${r.ingresos}

INSTRUCCIONES CRÍTICAS:
1. Las cifras deben ser REALISTAS según estadísticas españolas 2024-2025. NO subestimes. Una familia media española gasta entre 2.500€ y 4.500€/mes en total según el INE.
2. Incluye TODOS los gastos, incluyendo los que la gente olvida: seguros, educación, ropa, higiene, farmacia, mantenimiento del hogar, gastos bancarios, suscripciones.
3. Calibra según los ingresos declarados: si gana 4.000€/mes, sus gastos reales serán acordes a ese nivel.
4. Para los seguros declarados, estima costes reales: seguro coche ~600-1.200€/año, hogar ~200-400€/año, vida ~200-600€/año, médico privado ~100-300€/mes por persona.
5. Para educación: concertado ~100-200€/mes, privado ~400-800€/mes, universidad privada ~800-1.500€/mes, extraescolares ~80-200€/mes por hijo.
6. Para ropa: usa exactamente el nivel declarado (muy bajo ~50€, moderado ~100€, alto ~200€, muy alto ~350€+ al mes).

Genera el informe en HTML limpio con esta estructura exacta:

<div class="intro-personal">Párrafo de introducción muy personalizado para ESTA familia concreta. Menciona su comunidad, composición familiar y resume el gasto total estimado y el potencial de ahorro.</div>

<h3>📊 Así se reparte vuestro gasto mensual real</h3>
Para CADA categoría:
<div class="gasto-categoria" data-categoria="NOMBRE_CORTO" data-importe="NUMERO_ENTERO">
<h4>EMOJI Nombre de la categoría</h4>
<p>Explicación específica para esta familia. Menciona por qué ese importe concreto para su perfil.</p>
<div class="gasto-desglose">Concepto 1 (XX€) · Concepto 2 (XX€) · Concepto 3 (XX€)</div>
</div>

Categorías OBLIGATORIAS (no omitas ninguna):
- Vivienda (hipoteca/alquiler/mantenimiento/comunidad)
- Alimentación (compra + restaurantes calibrado según supermercados y frecuencia fuera)
- Energía (luz, gas, agua según sistema energético y tamaño vivienda)
- Transporte (combustible/bono transporte + mantenimiento/seguro coche + amortización)
- Seguros (desglose exacto de cada seguro declarado con precio real)
- Educación (solo si aplica: matrícula + extraescolares + material + comedor + transporte escolar)
- Ropa y calzado (según nivel declarado, para toda la familia)
- Ocio y entretenimiento (según estilo de vida: streaming, salidas, hobbies, vacaciones prorrateadas)
- Comunicaciones (internet, móviles)
- Salud y farmacia (medicamentos, copagos, dentista, óptica)
- Higiene y cuidado personal (productos, peluquería, cosmética)
- Hogar y mantenimiento (limpieza, pequeñas reparaciones, electrodomésticos amortizados)
- Gastos bancarios y financieros (comisiones, tarjetas, amortización créditos si aplica)
- Gastos invisibles y varios (cafés, regalos, lotería, compras impulsivas, suscripciones olvidadas)

<h3>🎯 Vuestras mejores oportunidades de ahorro</h3>
<div class="oportunidad-ahorro" data-ahorro="NUMERO">
<strong>TITULO</strong><p>Explicación específica con nombres reales (Lidl, Digi, Fintonic, comparador.cnmc.es, Acierto.com...).</p>
<div class="ahorro-badge">Ahorro estimado: XX€/mes</div>
</div>
(Mínimo 4 oportunidades concretas)

<h3>💡 Los gastos del día a día que no veis</h3>
<div class="gastos-invisibles"><ul><li>cada gasto invisible con estimación en euros</li></ul></div>

<h3>📅 Tres pasos concretos para esta semana</h3>
<ul class="plan-accion"><li>paso concreto y fácil</li></ul>

<div class="resumen-ahorro" data-total-ahorro="NUMERO_TOTAL_AHORRO">
<p>Resumen final: gasto total estimado, ahorro potencial mensual en euros, ahorro anual, porcentaje sobre ingresos.</p>
</div>

Tono: cercano, motivador, habla de "vosotros" si son familia o "tú" si vive solo. Solo HTML limpio, sin bloques de código.`;
}

function generarInformeLocal(r) {
  const personas = parseInt(r.personas) || 2;
  const ingresosNum = r.ingresos?.includes('6.000') ? 7000 : r.ingresos?.includes('4.000') ? 5000 : r.ingresos?.includes('2.500') ? 3200 : r.ingresos?.includes('1.500') ? 2000 : 1200;
  const baseAlimentacion = personas * 200;
  const baseEnergia = r.sistemaEnergetico?.includes('gas') ? 90 : 120;
  const baseTransporte = r.transporte?.includes('gasolina') ? 220 : r.transporte?.includes('publico') ? 80 : 30;
  const baseSeguros = (r.seguros?.split(',').length || 1) * 60;
  const baseEducacion = r.tipoEducacion?.includes('privado') ? 600 : r.tipoEducacion?.includes('concertado') ? 200 : r.tipoEducacion?.includes('universidad privada') ? 1000 : r.tipoEducacion?.includes('universidad') ? 300 : r.tipoEducacion?.includes('publico') ? 80 : 0;
  const baseRopa = r.gastoRopa?.includes('muy alto') ? 350 : r.gastoRopa?.includes('alto') ? 200 : r.gastoRopa?.includes('moderado') ? 100 : 50;
  const baseOcio = r.estiloVida?.includes('social') ? 400 : r.estiloVida?.includes('activo') ? 250 : r.estiloVida?.includes('ahorra') ? 80 : 180;
  const baseVivienda = r.situacionVivienda?.includes('hipoteca') ? 700 : r.situacionVivienda?.includes('alquiler') ? 650 : 150;
  const baseComunicaciones = 90;
  const baseSalud = personas * 25;
  const baseHigiene = personas * 30;
  const baseHogar = 80;
  const baseInvisibles = Math.round(ingresosNum * 0.05);
  const total = baseVivienda + baseAlimentacion + baseEnergia + baseTransporte + baseSeguros + baseEducacion + baseRopa + baseOcio + baseComunicaciones + baseSalud + baseHigiene + baseHogar + baseInvisibles;
  const ahorroEstimado = Math.round(total * 0.20);

  return `<div class="intro-personal">Hemos analizado la situación de vuestra familia de <strong>${personas} personas</strong> en <strong>${r.comunidad}</strong>. Con un estilo de vida <strong>${r.estiloVida}</strong>, estimamos un gasto mensual total de <strong>${total.toLocaleString('es-ES')}€</strong>. Aplicando las recomendaciones de este informe podéis ahorrar hasta <strong>${ahorroEstimado.toLocaleString('es-ES')}€ al mes</strong>.</div>
<h3>📊 Así se reparte vuestro gasto mensual real</h3>
<div class="gasto-categoria" data-categoria="Vivienda" data-importe="${baseVivienda}"><h4>🏠 Vivienda</h4><p>Con vuestra vivienda ${r.situacionVivienda} en ${r.comunidad}, el gasto en vivienda incluye ${r.situacionVivienda?.includes('hipoteca') ? 'la hipoteca mensual' : r.situacionVivienda?.includes('alquiler') ? 'el alquiler mensual' : 'el mantenimiento'}, comunidad de propietarios, IBI prorrateado y reparaciones.</p><div class="gasto-desglose">${r.situacionVivienda?.includes('hipoteca') ? 'Hipoteca (~550€)' : r.situacionVivienda?.includes('alquiler') ? 'Alquiler (~550€)' : 'Mantenimiento (~80€)'} · Comunidad (${Math.round(baseVivienda*0.10)}€) · IBI/seguros hogar prorrateados (${Math.round(baseVivienda*0.10)}€)</div></div>
<div class="gasto-categoria" data-categoria="Alimentación" data-importe="${baseAlimentacion}"><h4>🛒 Alimentación</h4><p>Para ${personas} personas comprando en ${r.supermercados || 'vuestros supermercados'} y comiendo fuera ${r.comerFuera}. Incluye desayuno, comida y cena para toda la familia más las salidas a restaurantes.</p><div class="gasto-desglose">Compra supermercado (${Math.round(baseAlimentacion*0.70)}€) · Restaurantes/fuera (${Math.round(baseAlimentacion*0.20)}€) · Extras y caprichos (${Math.round(baseAlimentacion*0.10)}€)</div></div>
<div class="gasto-categoria" data-categoria="Energía" data-importe="${baseEnergia}"><h4>⚡ Energía</h4><p>Con ${r.sistemaEnergetico} en ${r.metrosVivienda || '90'}m² en ${r.comunidad}. El clima de vuestra zona determina el consumo de calefacción y refrigeración.</p><div class="gasto-desglose">Electricidad (${Math.round(baseEnergia*0.50)}€) · ${r.sistemaEnergetico?.includes('gas') ? 'Gas natural' : 'Energía calefacción'} (${Math.round(baseEnergia*0.35)}€) · Agua (${Math.round(baseEnergia*0.15)}€)</div></div>
<div class="gasto-categoria" data-categoria="Transporte" data-importe="${baseTransporte}"><h4>🚗 Transporte</h4><p>Con ${r.transporte} y distancia al trabajo de ${r.distanciaTrabajo}. Incluye combustible o abono transporte, mantenimiento del vehículo y amortización.</p><div class="gasto-desglose">Combustible/abono (${Math.round(baseTransporte*0.60)}€) · Mantenimiento/seguro (${Math.round(baseTransporte*0.30)}€) · Parking/peajes (${Math.round(baseTransporte*0.10)}€)</div></div>
<div class="gasto-categoria" data-categoria="Seguros" data-importe="${baseSeguros}"><h4>🛡️ Seguros</h4><p>Tenéis contratados: ${r.seguros || 'seguros no declarados'}. Los seguros suponen un gasto fijo importante que muchas familias subestiman.</p><div class="gasto-desglose">Seguros contratados distribuidos mensualmente (${baseSeguros}€ total)</div></div>
${baseEducacion > 0 ? `<div class="gasto-categoria" data-categoria="Educación" data-importe="${baseEducacion}"><h4>📚 Educación</h4><p>Con ${r.tipoEducacion} y extras de ${r.extrasEducacion || 'ninguno'}, la educación es una inversión importante en vuestra familia.</p><div class="gasto-desglose">Matrícula/cuotas (${Math.round(baseEducacion*0.60)}€) · Extraescolares/academia (${Math.round(baseEducacion*0.25)}€) · Material/libros/comedor (${Math.round(baseEducacion*0.15)}€)</div></div>` : ''}
<div class="gasto-categoria" data-categoria="Ropa" data-importe="${baseRopa}"><h4>👕 Ropa y calzado</h4><p>Con un nivel de gasto en ropa ${r.gastoRopa?.split('(')[0] || 'moderado'} para ${personas} personas. Incluye renovación de armario, calzado y complementos a lo largo del año.</p><div class="gasto-desglose">Ropa adultos (${Math.round(baseRopa*0.60)}€) · Calzado (${Math.round(baseRopa*0.25)}€) · Complementos/otros (${Math.round(baseRopa*0.15)}€)</div></div>
<div class="gasto-categoria" data-categoria="Ocio" data-importe="${baseOcio}"><h4>🎬 Ocio y entretenimiento</h4><p>Con un estilo de vida ${r.estiloVida?.split('(')[0] || 'mixto'}, el ocio incluye plataformas digitales, salidas, hobbies y vacaciones prorrateadas.</p><div class="gasto-desglose">Plataformas/suscripciones (${Math.round(baseOcio*0.15)}€) · Salidas y actividades (${Math.round(baseOcio*0.50)}€) · Vacaciones prorrateadas (${Math.round(baseOcio*0.35)}€)</div></div>
<div class="gasto-categoria" data-categoria="Comunicaciones" data-importe="${baseComunicaciones}"><h4>📱 Comunicaciones</h4><p>Internet y líneas de móvil para vuestra familia en ${r.comunidad}.</p><div class="gasto-desglose">Fibra + router (40€) · Líneas móviles (${baseComunicaciones-40}€)</div></div>
<div class="gasto-categoria" data-categoria="Salud" data-importe="${baseSalud}"><h4>🏥 Salud y farmacia</h4><p>Medicamentos, copagos sanitarios, dentista y óptica para ${personas} personas. Un gasto real que suele sorprender al sumarlo.</p><div class="gasto-desglose">Farmacia y medicamentos (${Math.round(baseSalud*0.50)}€) · Dentista/óptica (${Math.round(baseSalud*0.30)}€) · Otros sanitarios (${Math.round(baseSalud*0.20)}€)</div></div>
<div class="gasto-categoria" data-categoria="Higiene" data-importe="${baseHigiene}"><h4>🧴 Higiene y cuidado personal</h4><p>Productos de higiene, cosmética, peluquería y cuidado personal para ${personas} personas.</p><div class="gasto-desglose">Productos higiene (${Math.round(baseHigiene*0.40)}€) · Cosmética/cuidado (${Math.round(baseHigiene*0.35)}€) · Peluquería/barbería (${Math.round(baseHigiene*0.25)}€)</div></div>
<div class="gasto-categoria" data-categoria="Hogar" data-importe="${baseHogar}"><h4>🔧 Hogar y mantenimiento</h4><p>Productos de limpieza, pequeñas reparaciones y mantenimiento general de la vivienda.</p><div class="gasto-desglose">Limpieza y consumibles (${Math.round(baseHogar*0.50)}€) · Reparaciones/bricolaje (${Math.round(baseHogar*0.30)}€) · Electrodomésticos amortizados (${Math.round(baseHogar*0.20)}€)</div></div>
<div class="gasto-categoria" data-categoria="Gastos invisibles" data-importe="${baseInvisibles}"><h4>👻 Gastos invisibles y varios</h4><p>Los gastos que nunca aparecen en el presupuesto pero que al sumarlos sorprenden. Para vuestra familia estimamos entre ${Math.round(baseInvisibles*0.8)}€ y ${Math.round(baseInvisibles*1.2)}€ al mes.</p><div class="gasto-desglose">Cafés y consumiciones (${Math.round(baseInvisibles*0.25)}€) · Compras impulsivas (${Math.round(baseInvisibles*0.30)}€) · Suscripciones olvidadas (${Math.round(baseInvisibles*0.15)}€) · Regalos/celebraciones (${Math.round(baseInvisibles*0.20)}€) · Otros (${Math.round(baseInvisibles*0.10)}€)</div></div>
<h3>🎯 Vuestras mejores oportunidades de ahorro</h3>
<div class="oportunidad-ahorro" data-ahorro="${Math.round(baseAlimentacion*0.18)}"><strong>1. Optimizar la compra del supermercado</strong><p>Concentrad el 70% en <strong>Lidl o Aldi</strong> y usad <strong>Tiendeo</strong> antes de ir para ver ofertas. Para ${personas} personas el ahorro puede ser significativo.</p><div class="ahorro-badge">Ahorro: ${Math.round(baseAlimentacion*0.18)}€/mes</div></div>
<div class="oportunidad-ahorro" data-ahorro="45"><strong>2. Revisar la tarifa de móvil e internet</strong><p><strong>Digi</strong> ofrece fibra 1Gb + móvil ilimitado por 22€/mes. Llama al número de bajas de tu operadora actual — el 80% de las veces te mejoran la tarifa al momento.</p><div class="ahorro-badge">Ahorro: 45€/mes</div></div>
<div class="oportunidad-ahorro" data-ahorro="${Math.round(baseSeguros*0.20)}"><strong>3. Comparar y renegociar los seguros</strong><p>Usad <strong>Acierto.com</strong> o <strong>Rastreator.com</strong> para comparar vuestros seguros actuales. Las familias que comparan ahorran de media un 20-30% sin perder coberturas.</p><div class="ahorro-badge">Ahorro: ${Math.round(baseSeguros*0.20)}€/mes</div></div>
<div class="oportunidad-ahorro" data-ahorro="25"><strong>4. Optimizar el consumo eléctrico</strong><p>Activa la tarifa valle/punta y programa lavadora y lavavajillas entre las 00:00 y las 08:00. Compara tarifas en <strong>comparador.cnmc.es</strong> (gratis).</p><div class="ahorro-badge">Ahorro: 25€/mes</div></div>
<div class="oportunidad-ahorro" data-ahorro="${Math.round(baseInvisibles*0.30)}"><strong>5. Controlar los gastos invisibles</strong><p>Descarga <strong>Fintonic</strong> (gratis) y conecta tu banco. En el primer mes la mayoría de familias detecta entre 80€ y 150€ en gastos que no recordaban tener.</p><div class="ahorro-badge">Ahorro: ${Math.round(baseInvisibles*0.30)}€/mes</div></div>
<h3>💡 Los gastos del día a día que no veis</h3>
<div class="gastos-invisibles"><ul>
<li><strong>Cafés y consumiciones rápidas:</strong> 2 cafés/día por persona = ${personas * 45}€/mes</li>
<li><strong>Suscripciones digitales olvidadas:</strong> Apps, juegos, servicios caducados (15-30€/mes)</li>
<li><strong>Compras impulsivas online:</strong> Amazon, moda online, app stores (50-100€/mes)</li>
<li><strong>Comidas en el trabajo:</strong> Menú del día o bocadillo ~10€/día/persona trabajadora</li>
<li><strong>Farmacia sin receta:</strong> Vitaminas, complementos, productos de parafarmacia (20-40€/mes)</li>
<li><strong>Regalos y celebraciones:</strong> Cumpleaños, bodas, comuniones prorrateados (30-60€/mes)</li>
<li><strong>Pequeñas obras y bricolaje:</strong> Materiales, herramientas, pinturas (20-40€/mes de media)</li>
</ul></div>
<h3>📅 Tres pasos concretos para esta semana</h3>
<ul class="plan-accion">
<li><strong>Hoy:</strong> Descarga <strong>Fintonic</strong> y conecta tu cuenta bancaria. Revisa los últimos 2 meses de movimientos e identifica los 3 gastos más sorprendentes.</li>
<li><strong>Esta semana:</strong> Llama al número de bajas de tu operadora de teléfono e internet. Diles que estás pensando en irte a Digi. El 80% de las veces te mejoran la tarifa en el acto.</li>
<li><strong>Este fin de semana:</strong> Entra en Acierto.com y compara tus seguros actuales. Dedica 20 minutos y es probable que encuentres un ahorro de ${Math.round(baseSeguros*0.20)}€/mes o más.</li>
</ul>
<div class="resumen-ahorro" data-total-ahorro="${ahorroEstimado}">
<p>Vuestro gasto mensual real estimado es de <strong>${total.toLocaleString('es-ES')}€</strong>. Aplicando las recomendaciones de este informe podéis ahorrar entre <strong>${ahorroEstimado}€ y ${Math.round(ahorroEstimado*1.3)}€ al mes</strong>, lo que supone <strong>${ahorroEstimado*12}€ al año</strong> — entre el <strong>${Math.round(ahorroEstimado/ingresosNum*100)}% y el ${Math.round(ahorroEstimado*1.3/ingresosNum*100)}%</strong> de vuestros ingresos.</p>
</div>`;
}

function extraerAhorro(html) {
  const match = html.match(/data-total-ahorro="(\d+)"/);
  return match ? parseInt(match[1]) : 0;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Ahurus server corriendo en puerto ${PORT}`));
