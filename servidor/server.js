const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const crypto = require('crypto');   // incluido en Node: hash de contraseñas y tokens de sesión

const app = express();
app.use(cors());
app.use(express.json({ limit: '100kb' }));

// Conexión a la base de datos pasteleria
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'admin',
    database: 'pasteleria',
    decimalNumbers: true   // devuelve los DECIMAL como números y no como texto
});

db.connect(err => {
    if (err) {
        console.error('Error al conectar a la BD pasteleria:', err);
        return;
    }
    console.log('Conectado exitosamente a la base de datos pasteleria');
    protegerContrasenas();
});

/* HELPERS-INICIO */

/* =====================================================
   VALIDACIONES (tipo de dato, longitud y rango)
   ===================================================== */
const CATEGORIAS = ['Tortas', 'Individuales', 'Salados'];
const ROLES = ['Administrador', 'Encargado de Ventas'];

const esNumero = (v, min, max) => typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max;
const esEntero = (v, min, max) => Number.isInteger(v) && v >= min && v <= max;
const dosDecimales = v => Math.abs(v * 100 - Math.round(v * 100)) < 1e-6;
const texto = v => (typeof v === 'string' ? v.trim() : '');

// Política de contraseña: 8+ caracteres, minúscula, mayúscula, dígito y símbolo especial
function errorPassword(p) {
    if (typeof p !== 'string') return 'La contraseña es obligatoria';
    if (p.length > 64) return 'La contraseña no puede superar los 64 caracteres';
    const faltan = [];
    if (p.length < 8) faltan.push('mínimo 8 caracteres');
    if (!/[a-z]/.test(p)) faltan.push('una letra minúscula');
    if (!/[A-Z]/.test(p)) faltan.push('una letra mayúscula');
    if (!/\d/.test(p)) faltan.push('un dígito');
    if (!/[^A-Za-z0-9\s]/.test(p)) faltan.push('un símbolo especial');
    return faltan.length ? 'La contraseña debe tener ' + faltan.join(', ') : null;
}

function validarProducto(b) {
    const name = texto(b.name);
    if (name.length < 2 || name.length > 100) return { error: 'El nombre debe tener entre 2 y 100 caracteres' };
    if (!CATEGORIAS.includes(b.category)) return { error: 'La categoría no es válida' };
    if (!esNumero(b.price, 0.1, 9999.99) || !dosDecimales(b.price)) {
        return { error: 'El precio debe estar entre S/ 0.10 y S/ 9999.99 (máximo 2 decimales)' };
    }
    if (!esEntero(b.stock, 0, 9999)) return { error: 'El stock debe ser un número entero entre 0 y 9999' };
    const image = texto(b.image);
    if (image.length > 255 || !/^https?:\/\/\S+$/i.test(image)) {
        return { error: 'La imagen debe ser una URL http(s) de hasta 255 caracteres' };
    }
    return { datos: { name, category: b.category, price: b.price, stock: b.stock, image } };
}

function validarUsuario(b, esNuevo) {
    const username = texto(b.username);
    if (!/^[A-Za-z0-9_.]{4,30}$/.test(username)) {
        return { error: 'El usuario debe tener de 4 a 30 caracteres (letras, números, punto o guion bajo)' };
    }
    const name = texto(b.name);
    if (name.length < 3 || name.length > 80) return { error: 'El nombre completo debe tener entre 3 y 80 caracteres' };
    if (!ROLES.includes(b.role)) return { error: 'El rol no es válido' };

    let password;
    if (esNuevo || (typeof b.password === 'string' && b.password !== '')) {
        const e = errorPassword(b.password);
        if (e) return { error: e };
        password = b.password;
    }
    return { datos: { username, name, role: b.role, password } };
}

/* =====================================================
   CONTRASEÑAS (hash con scrypt, sin librerías externas)
   ===================================================== */
function hashPassword(plano) {
    const sal = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(plano, sal, 32).toString('hex');
    return `scrypt$${sal}$${hash}`;
}

function verificarPassword(plano, guardado) {
    if (typeof guardado !== 'string') return false;
    const partes = guardado.split('$');
    if (partes.length !== 3 || partes[0] !== 'scrypt') return false;
    const esperado = Buffer.from(partes[2], 'hex');
    if (esperado.length === 0) return false;
    const calculado = crypto.scryptSync(plano, partes[1], esperado.length);
    return crypto.timingSafeEqual(calculado, esperado);
}

/* HELPERS-FIN */

// Al iniciar, convierte a hash cualquier contraseña que aún esté en texto plano
function protegerContrasenas() {
    const query = "SELECT codigo_usuario, password FROM Usuario WHERE password NOT LIKE 'scrypt$%'";
    db.query(query, (err, filas) => {
        if (err) return console.error('No se pudieron revisar las contraseñas:', err.message);
        filas.forEach(f => {
            const q = 'UPDATE Usuario SET password = ? WHERE codigo_usuario = ?';
            db.query(q, [hashPassword(f.password), f.codigo_usuario], err => {
                if (err) console.error('No se pudo proteger la contraseña:', err.message);
            });
        });
        if (filas.length > 0) console.log(`Contraseñas protegidas con hash: ${filas.length}`);
    });
}

// Respuesta de error común para todos los endpoints
function responderError(res, err, mensajeDuplicado) {
    if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ message: mensajeDuplicado || 'Ya existe un registro con ese valor' });
    }
    if (err.code === 'ER_ROW_IS_REFERENCED_2') {
        return res.status(409).json({
            message: 'No se puede eliminar definitivamente: tiene ventas registradas. Puedes desactivarlo.'
        });
    }
    res.status(500).json({ error: err.message });
}

function idValido(req, res) {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
        res.status(400).json({ message: 'Identificador no válido' });
        return null;
    }
    return id;
}

/* =====================================================
   SESIONES Y AUTORIZACIÓN
   ===================================================== */
const sesiones = new Map();                      // token -> datos del usuario
const DURACION_SESION = 8 * 60 * 60 * 1000;      // 8 horas

// Exige un token válido (cualquier perfil)
function autenticar(req, res, next) {
    const cabecera = req.headers.authorization || '';
    const token = cabecera.startsWith('Bearer ') ? cabecera.slice(7) : '';
    const sesion = sesiones.get(token);
    if (!sesion || sesion.expira < Date.now()) {
        sesiones.delete(token);
        return res.status(401).json({ message: 'Sesión no válida o expirada' });
    }
    req.usuario = sesion;
    req.token = token;
    next();
}

// Exige además el perfil de administrador
function soloAdmin(req, res, next) {
    if (req.usuario.role !== 'Administrador') {
        return res.status(403).json({ message: 'Acceso restringido a administradores' });
    }
    next();
}

function cerrarSesionesDe(idUsuario) {
    for (const [token, s] of sesiones) {
        if (s.id === idUsuario) sesiones.delete(token);
    }
}

/* =====================================================
   LOGIN / LOGOUT
   ===================================================== */
app.post('/api/login', (req, res) => {
    const { username, password } = req.body || {};
    const usuario = texto(username);
    if (!usuario || usuario.length > 30 || typeof password !== 'string' || !password || password.length > 64) {
        return res.status(400).json({ message: 'Ingresa un usuario y una contraseña válidos' });
    }

    const query = `
        SELECT codigo_usuario AS id, username, nombre AS name, rol AS role, password, estado
        FROM Usuario
        WHERE username = ?;
    `;
    db.query(query, [usuario], (err, result) => {
        if (err) return responderError(res, err);
        if (result.length === 0 || !verificarPassword(password, result[0].password)) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }
        const u = result[0];
        if (u.estado !== 1) return res.status(403).json({ message: 'Usuario inactivo. Contacta al administrador' });

        const token = crypto.randomBytes(32).toString('hex');
        const datos = { id: u.id, username: u.username, name: u.name, role: u.role };
        sesiones.set(token, { ...datos, expira: Date.now() + DURACION_SESION });
        res.json({ token, usuario: datos });
    });
});

app.post('/api/logout', autenticar, (req, res) => {
    sesiones.delete(req.token);
    res.json({ message: 'Sesión cerrada' });
});

/* =====================================================
   PRODUCTOS
   (ver: cualquier perfil | crear, editar, desactivar y eliminar: solo admin)
   ===================================================== */
app.get('/api/productos', autenticar, (req, res) => {
    // El admin puede pedir también los inactivos con ?todos=1
    const verTodos = req.query.todos === '1' && req.usuario.role === 'Administrador';
    const query = `
        SELECT codigo_producto AS id, nombre AS name, categoria AS category,
               precio AS price, stock, imagen AS image, estado
        FROM Producto
        ${verTodos ? '' : 'WHERE estado = 1'}
        ORDER BY codigo_producto;
    `;
    db.query(query, (err, result) => {
        if (err) return responderError(res, err);
        res.json(result);
    });
});

app.post('/api/productos', autenticar, soloAdmin, (req, res) => {
    const { error, datos } = validarProducto(req.body || {});
    if (error) return res.status(400).json({ message: error });

    const query = `
        INSERT INTO Producto (nombre, categoria, precio, stock, imagen, estado)
        VALUES (?, ?, ?, ?, ?, 1);
    `;
    db.query(query, [datos.name, datos.category, datos.price, datos.stock, datos.image], (err, result) => {
        if (err) return responderError(res, err);
        res.status(201).json({ id: result.insertId, ...datos, estado: 1 });
    });
});

app.put('/api/productos/:id', autenticar, soloAdmin, (req, res) => {
    const id = idValido(req, res);
    if (id === null) return;
    const { error, datos } = validarProducto(req.body || {});
    if (error) return res.status(400).json({ message: error });

    const query = `
        UPDATE Producto
        SET nombre = ?, categoria = ?, precio = ?, stock = ?, imagen = ?
        WHERE codigo_producto = ?;
    `;
    db.query(query, [datos.name, datos.category, datos.price, datos.stock, datos.image, id], (err, result) => {
        if (err) return responderError(res, err);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Producto no encontrado' });
        res.json({ id, ...datos });
    });
});

// ELIMINACIÓN LÓGICA: desactiva o reactiva (el registro se conserva)
app.patch('/api/productos/:id/estado', autenticar, soloAdmin, (req, res) => {
    const id = idValido(req, res);
    if (id === null) return;
    const estado = (req.body || {}).estado;
    if (estado !== 0 && estado !== 1) return res.status(400).json({ message: 'El estado debe ser 0 o 1' });

    db.query('UPDATE Producto SET estado = ? WHERE codigo_producto = ?', [estado, id], (err, result) => {
        if (err) return responderError(res, err);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Producto no encontrado' });
        res.json({ id, estado });
    });
});

// ELIMINACIÓN FÍSICA: borra el registro definitivamente
app.delete('/api/productos/:id', autenticar, soloAdmin, (req, res) => {
    const id = idValido(req, res);
    if (id === null) return;

    db.query('DELETE FROM Producto WHERE codigo_producto = ?', [id], (err, result) => {
        if (err) return responderError(res, err);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Producto no encontrado' });
        res.json({ message: 'Producto eliminado definitivamente' });
    });
});

/* =====================================================
   USUARIOS (solo administrador)
   ===================================================== */
app.get('/api/usuarios', autenticar, soloAdmin, (req, res) => {
    const query = `
        SELECT codigo_usuario AS id, username, nombre AS name, rol AS role, estado
        FROM Usuario
        ORDER BY codigo_usuario;
    `;
    db.query(query, (err, result) => {
        if (err) return responderError(res, err);
        res.json(result);
    });
});

app.post('/api/usuarios', autenticar, soloAdmin, (req, res) => {
    const { error, datos } = validarUsuario(req.body || {}, true);
    if (error) return res.status(400).json({ message: error });

    const query = `
        INSERT INTO Usuario (username, nombre, rol, password, estado)
        VALUES (?, ?, ?, ?, 1);
    `;
    db.query(query, [datos.username, datos.name, datos.role, hashPassword(datos.password)], (err, result) => {
        if (err) return responderError(res, err, 'Ya existe un usuario con ese nombre de usuario');
        res.status(201).json({ id: result.insertId, username: datos.username, name: datos.name, role: datos.role, estado: 1 });
    });
});

app.put('/api/usuarios/:id', autenticar, soloAdmin, (req, res) => {
    const id = idValido(req, res);
    if (id === null) return;
    const { error, datos } = validarUsuario(req.body || {}, false);
    if (error) return res.status(400).json({ message: error });

    // Un administrador no puede quitarse a sí mismo el perfil de administrador
    if (id === req.usuario.id && datos.role !== req.usuario.role) {
        return res.status(400).json({ message: 'No puedes cambiar tu propio rol' });
    }

    // Si no se envía contraseña, se conserva la actual
    let query = 'UPDATE Usuario SET username = ?, nombre = ?, rol = ?';
    const params = [datos.username, datos.name, datos.role];
    if (datos.password) {
        query += ', password = ?';
        params.push(hashPassword(datos.password));
    }
    query += ' WHERE codigo_usuario = ?';
    params.push(id);

    db.query(query, params, (err, result) => {
        if (err) return responderError(res, err, 'Ya existe un usuario con ese nombre de usuario');
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Usuario no encontrado' });

        // Los cambios de nombre o rol se reflejan en sus sesiones abiertas
        for (const s of sesiones.values()) {
            if (s.id === id) { s.username = datos.username; s.name = datos.name; s.role = datos.role; }
        }
        res.json({ id, username: datos.username, name: datos.name, role: datos.role });
    });
});

// ELIMINACIÓN LÓGICA: un usuario inactivo no puede iniciar sesión
app.patch('/api/usuarios/:id/estado', autenticar, soloAdmin, (req, res) => {
    const id = idValido(req, res);
    if (id === null) return;
    const estado = (req.body || {}).estado;
    if (estado !== 0 && estado !== 1) return res.status(400).json({ message: 'El estado debe ser 0 o 1' });
    if (id === req.usuario.id && estado === 0) {
        return res.status(400).json({ message: 'No puedes desactivar tu propia cuenta' });
    }

    db.query('UPDATE Usuario SET estado = ? WHERE codigo_usuario = ?', [estado, id], (err, result) => {
        if (err) return responderError(res, err);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Usuario no encontrado' });
        if (estado === 0) cerrarSesionesDe(id);
        res.json({ id, estado });
    });
});

// ELIMINACIÓN FÍSICA
app.delete('/api/usuarios/:id', autenticar, soloAdmin, (req, res) => {
    const id = idValido(req, res);
    if (id === null) return;
    if (id === req.usuario.id) return res.status(400).json({ message: 'No puedes eliminar tu propia cuenta' });

    db.query('DELETE FROM Usuario WHERE codigo_usuario = ?', [id], (err, result) => {
        if (err) return responderError(res, err);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Usuario no encontrado' });
        cerrarSesionesDe(id);
        res.json({ message: 'Usuario eliminado definitivamente' });
    });
});

/* =====================================================
   VENTAS (cualquier perfil con sesión iniciada)
   ===================================================== */

// Consulta maestro (Venta) + detalle (DetalleVenta) y los une en un solo arreglo
function consultarVentas(where, params, callback) {
    const queryMaestro = `
        SELECT v.codigo_venta AS codigo, v.numero_doc AS id, v.tipo_doc AS docType,
               DATE_FORMAT(v.fecha, '%Y-%m-%d %H:%i') AS date,
               v.cliente AS customer, u.nombre AS user,
               v.subtotal, v.igv, v.total, v.pagado AS paid, v.vuelto AS \`change\`
        FROM Venta v
        INNER JOIN Usuario u ON v.codigo_usuario = u.codigo_usuario
        ${where}
        ORDER BY v.fecha DESC, v.codigo_venta DESC;
    `;
    const queryDetalle = `
        SELECT d.codigo_venta, p.codigo_producto AS id, p.nombre AS name,
               d.precio_unit AS price, d.cantidad AS qty,
               (d.cantidad * d.precio_unit) AS total
        FROM DetalleVenta d
        INNER JOIN Producto p ON d.codigo_producto = p.codigo_producto
        WHERE d.codigo_venta IN (?);
    `;

    db.query(queryMaestro, params, (err, ventas) => {
        if (err) return callback(err);
        if (ventas.length === 0) return callback(null, []);

        db.query(queryDetalle, [ventas.map(v => v.codigo)], (err, detalles) => {
            if (err) return callback(err);
            ventas.forEach(v => {
                v.items = detalles
                    .filter(d => d.codigo_venta === v.codigo)
                    .map(({ codigo_venta, ...item }) => item);
            });
            callback(null, ventas);
        });
    });
}

// Historial de ventas. Filtros opcionales: ?fecha=2026-09-23&texto=carlos
app.get('/api/ventas', autenticar, (req, res) => {
    const condiciones = [];
    const params = [];

    if (req.query.fecha) {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(req.query.fecha)) {
            return res.status(400).json({ message: 'La fecha debe tener el formato AAAA-MM-DD' });
        }
        condiciones.push('DATE(v.fecha) = ?');
        params.push(req.query.fecha);
    }
    if (req.query.texto) {
        if (typeof req.query.texto !== 'string' || req.query.texto.length > 100) {
            return res.status(400).json({ message: 'El texto de búsqueda no puede superar los 100 caracteres' });
        }
        condiciones.push('(v.cliente LIKE ? OR v.numero_doc LIKE ?)');
        params.push(`%${req.query.texto}%`, `%${req.query.texto}%`);
    }
    const where = condiciones.length ? 'WHERE ' + condiciones.join(' AND ') : '';

    consultarVentas(where, params, (err, ventas) => {
        if (err) return responderError(res, err);
        res.json(ventas);
    });
});

// Una venta (para reimprimir el comprobante)
app.get('/api/ventas/:codigo', autenticar, (req, res) => {
    const codigo = Number(req.params.codigo);
    if (!Number.isInteger(codigo) || codigo <= 0) {
        return res.status(400).json({ message: 'Identificador no válido' });
    }
    consultarVentas('WHERE v.codigo_venta = ?', [codigo], (err, ventas) => {
        if (err) return responderError(res, err);
        if (ventas.length === 0) return res.status(404).json({ message: 'Venta no encontrada' });
        res.json(ventas[0]);
    });
});

// Registrar una venta (con transacción)
// Body: { docType, customer, paid, items: [{ id, qty }] }
// El vendedor se toma de la sesión, no del cuerpo de la petición.
app.post('/api/ventas', autenticar, (req, res) => {
    const { docType, customer, paid, items } = req.body || {};

    if (docType !== 'Boleta' && docType !== 'Factura') {
        return res.status(400).json({ message: 'El tipo de comprobante debe ser Boleta o Factura' });
    }
    const cliente = texto(customer) || 'Cliente Varios';
    if (cliente.length > 100) {
        return res.status(400).json({ message: 'El nombre del cliente no puede superar los 100 caracteres' });
    }
    if (!esNumero(paid, 0, 99999.99)) {
        return res.status(400).json({ message: 'El monto entregado debe estar entre 0 y 99999.99' });
    }
    if (!Array.isArray(items) || items.length < 1 || items.length > 50) {
        return res.status(400).json({ message: 'La venta debe tener entre 1 y 50 productos' });
    }

    // Une los productos repetidos y valida cada línea
    const cantidades = new Map();
    for (const item of items) {
        if (!item || !esEntero(item.id, 1, 2147483647) || !esEntero(item.qty, 1, 999)) {
            return res.status(400).json({ message: 'Producto o cantidad inválida (la cantidad debe ser de 1 a 999)' });
        }
        cantidades.set(item.id, (cantidades.get(item.id) || 0) + item.qty);
    }
    const lineas = [...cantidades].map(([id, qty]) => ({ id, qty }));

    const tipoDoc = docType;
    const prefijo = tipoDoc === 'Boleta' ? 'B001' : 'F001';
    const pagado = paid;
    const userId = req.usuario.id;
    const redondear = n => Math.round(n * 100) / 100;

    db.beginTransaction(err => {
        if (err) return responderError(res, err);

        const cancelar = (status, body) => db.rollback(() => res.status(status).json(body));

        // 1. Leer precios y stock reales desde la BD (solo productos activos)
        const ids = lineas.map(l => l.id);
        const queryProductos = `
            SELECT codigo_producto, nombre, precio, stock
            FROM Producto
            WHERE codigo_producto IN (?) AND estado = 1
            FOR UPDATE;
        `;
        db.query(queryProductos, [ids], (err, productos) => {
            if (err) return cancelar(500, { error: err.message });

            let total = 0;
            const detalle = [];
            for (const linea of lineas) {
                const prod = productos.find(p => p.codigo_producto === linea.id);
                if (!prod) {
                    return cancelar(400, { message: 'Uno de los productos no existe o está inactivo' });
                }
                if (prod.stock < linea.qty) {
                    return cancelar(400, { message: `Stock insuficiente de ${prod.nombre}` });
                }
                total += prod.precio * linea.qty;
                detalle.push({ codigo: prod.codigo_producto, cantidad: linea.qty, precio: prod.precio });
            }

            total = redondear(total);
            if (pagado < total) {
                return cancelar(400, { message: 'El monto entregado es menor al total de la venta' });
            }
            const igv = redondear(total * 0.18);
            const subtotal = redondear(total - igv);
            const vuelto = redondear(pagado - total);

            // 2. Siguiente número correlativo (B001-000102, F001-000043, ...)
            const queryUltimo = `
                SELECT MAX(CAST(SUBSTRING_INDEX(numero_doc, '-', -1) AS UNSIGNED)) AS ultimo
                FROM Venta
                WHERE tipo_doc = ?;
            `;
            db.query(queryUltimo, [tipoDoc], (err, r) => {
                if (err) return cancelar(500, { error: err.message });
                const numeroDoc = `${prefijo}-${String((r[0].ultimo || 0) + 1).padStart(6, '0')}`;

                // 3. Insertar la cabecera de la venta
                const queryVenta = `
                    INSERT INTO Venta (numero_doc, tipo_doc, fecha, cliente, codigo_usuario,
                                       subtotal, igv, total, pagado, vuelto)
                    VALUES (?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?);
                `;
                const paramsVenta = [numeroDoc, tipoDoc, cliente, userId, subtotal, igv, total, pagado, vuelto];
                db.query(queryVenta, paramsVenta, (err, ventaRes) => {
                    if (err) return cancelar(500, { error: err.message });
                    const codigoVenta = ventaRes.insertId;

                    // 4. Insertar el detalle
                    const filas = detalle.map(d => [codigoVenta, d.codigo, d.cantidad, d.precio]);
                    const queryDetalle = `
                        INSERT INTO DetalleVenta (codigo_venta, codigo_producto, cantidad, precio_unit)
                        VALUES ?;
                    `;
                    db.query(queryDetalle, [filas], err => {
                        if (err) return cancelar(500, { error: err.message });

                        // 5. Descontar stock producto por producto y confirmar
                        const descontar = i => {
                            if (i === detalle.length) {
                                return db.commit(err => {
                                    if (err) return cancelar(500, { error: err.message });
                                    consultarVentas('WHERE v.codigo_venta = ?', [codigoVenta], (err, ventas) => {
                                        if (err) return responderError(res, err);
                                        res.status(201).json(ventas[0]);
                                    });
                                });
                            }
                            const queryStock = 'UPDATE Producto SET stock = stock - ? WHERE codigo_producto = ?';
                            db.query(queryStock, [detalle[i].cantidad, detalle[i].codigo], err => {
                                if (err) return cancelar(500, { error: err.message });
                                descontar(i + 1);
                            });
                        };
                        descontar(0);
                    });
                });
            });
        });
    });
});

/* =====================================================
   DASHBOARD
   ===================================================== */
app.get('/api/ventas-resumen/mensual', autenticar, (req, res) => {
    const query = `
        SELECT mes, cantidad_ventas AS cantidadVentas, monto_total AS montoTotal
        FROM HistorialMensual
        ORDER BY codigo_mes;
    `;
    db.query(query, (err, result) => {
        if (err) return responderError(res, err);
        res.json(result);
    });
});

// JSON mal formado u otros errores de la petición
app.use((err, req, res, next) => {
    res.status(400).json({ message: 'Solicitud no válida' });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});