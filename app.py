import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from datetime import date
from sqlalchemy import exc, Table 
from sqlalchemy.orm import sessionmaker
from functools import wraps 


# 1. CONFIGURACIÓN INICIAL
load_dotenv()
app = Flask(__name__)

# Credenciales de la BD
DB_USER = os.environ.get('POSTGRES_USER', 'admin_cafe')
DB_PASS = os.environ.get('POSTGRES_PASSWORD', 'admin123')
DB_NAME = os.environ.get('POSTGRES_DB', 'cafeteria_db')
DB_HOST = os.environ.get('DB_HOST', 'db')
DB_PORT = '5432'

# URLs de conexión DCL
ADMIN_DB_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
BARISTA_DB_URL = f"postgresql://app_barista:barista_pass@{DB_HOST}:{DB_PORT}/{DB_NAME}"
GERENTE_DB_URL = f"postgresql://app_gerente:gerente_pass@{DB_HOST}:{DB_PORT}/{DB_NAME}"
CLIENTE_DB_URL = f"postgresql://app_cliente:cliente_pass@{DB_HOST}:{DB_PORT}/{DB_NAME}"

app.config['SECRET_KEY'] = 'esta-es-una-llave-secreta-muy-larga-y-dificil-de-adivinar'
app.config['SQLALCHEMY_DATABASE_URI'] = ADMIN_DB_URL 
app.config['SQLALCHEMY_BINDS'] = {
    'barista': BARISTA_DB_URL,
    'gerente': GERENTE_DB_URL,
    'cliente': CLIENTE_DB_URL
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, inicia sesión para acceder.'
login_manager.login_message_category = 'info'

# --- DECORADOR PARA RUTAS DE ADMIN ---
def admin_required(f):
    """Decorador para rutas exclusivas de 'admin'"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.rol != 'admin':
            flash('Acceso denegado. Esta área es solo para administradores.', 'danger')
            return redirect(url_for('menu'))
        return f(*args, **kwargs)
    return decorated_function


# 2. MODELOS DE BASE DE DATOS


# Tabla de asociación
proveedor_producto_association = db.Table('proveedor_producto',
    db.Column('id_proveedor', db.Integer, db.ForeignKey('proveedor.id_proveedor'), primary_key=True),
    db.Column('id_producto', db.Integer, db.ForeignKey('producto.id_producto'), primary_key=True)
)

class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuario'
    id = db.Column('id_usuario', db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(50), nullable=False)
    id_cliente = db.Column(db.Integer, db.ForeignKey('cliente.id_cliente'))
    id_empleado = db.Column(db.Integer, db.ForeignKey('empleado.id_empleado'))

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Empleado(db.Model):
    __tablename__ = 'empleado'
    id_empleado = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    puesto = db.Column(db.String(50), nullable=False)
    fecha_contratacion = db.Column(db.Date, nullable=False)
    usuario = db.relationship('Usuario', backref='empleado', uselist=False)

class Cliente(db.Model):
    __tablename__ = 'cliente'
    id_cliente = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    telefono = db.Column(db.String(20))
    

    calle = db.Column(db.String(100))
    numero_exterior = db.Column(db.String(20))
    colonia = db.Column(db.String(100))
    codigo_postal = db.Column(db.String(10))

    usuario = db.relationship('Usuario', backref='cliente', uselist=False)
    frecuente = db.relationship('Frecuente', backref='cliente', uselist=False, cascade="all, delete-orphan")
    ocasional = db.relationship('Ocasional', backref='cliente', uselist=False, cascade="all, delete-orphan")

class Producto(db.Model):
    __tablename__ = 'producto'
    id_producto = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False, unique=True)
    descripcion = db.Column(db.Text)
    precio_venta = db.Column(db.Numeric(10, 2), nullable=False)
    perecedero = db.relationship('Perecedero', backref='producto', uselist=False, cascade="all, delete-orphan")
    no_perecedero = db.relationship('NoPerecedero', backref='producto', uselist=False, cascade="all, delete-orphan")
    proveedores = db.relationship('Proveedor', secondary=proveedor_producto_association, back_populates='productos')

class Venta(db.Model):
    __tablename__ = 'venta'
    id_venta = db.Column(db.Integer, primary_key=True)
    fecha_hora = db.Column(db.TIMESTAMP, nullable=False, default=db.func.current_timestamp())
    monto_total = db.Column(db.Numeric(10, 2), nullable=False)
    id_cliente = db.Column(db.Integer, db.ForeignKey('cliente.id_cliente'), nullable=False)
    id_empleado = db.Column(db.Integer, db.ForeignKey('empleado.id_empleado'), nullable=False)
    
    cliente = db.relationship('Cliente', foreign_keys=[id_cliente])
    empleado = db.relationship('Empleado', foreign_keys=[id_empleado])
    detalles = db.relationship('DetalleVenta', backref='venta', lazy=True)

class DetalleVenta(db.Model):
    __tablename__ = 'detalle_venta'
    id_venta = db.Column(db.Integer, db.ForeignKey('venta.id_venta'), primary_key=True)
    id_producto = db.Column(db.Integer, db.ForeignKey('producto.id_producto'), primary_key=True)
    cantidad = db.Column(db.Integer, nullable=False)
    precio_unitario = db.Column(db.Numeric(10, 2), nullable=False)
    producto = db.relationship('Producto')

class Proveedor(db.Model):
    __tablename__ = 'proveedor'
    id_proveedor = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    telefonos = db.relationship('TelefonoProveedor', backref='proveedor', lazy='dynamic', cascade="all, delete-orphan")
    productos = db.relationship('Producto', secondary=proveedor_producto_association, back_populates='proveedores')

class Frecuente(db.Model):
    __tablename__ = 'frecuente'
    id_cliente = db.Column(db.Integer, db.ForeignKey('cliente.id_cliente'), primary_key=True)
    puntos_acumulados = db.Column(db.Integer, nullable=False, default=0)
    fecha_registro_vip = db.Column(db.Date, nullable=False, default=date.today)

class Ocasional(db.Model):
    __tablename__ = 'ocasional'
    id_cliente = db.Column(db.Integer, db.ForeignKey('cliente.id_cliente'), primary_key=True)
    ultima_fecha_visita = db.Column(db.Date)

class Perecedero(db.Model):
    __tablename__ = 'perecedero'
    id_producto = db.Column(db.Integer, db.ForeignKey('producto.id_producto'), primary_key=True)
    fecha_caducidad = db.Column(db.Date, nullable=False)
    condiciones_almacenamiento = db.Column(db.String(255))

class NoPerecedero(db.Model):
    __tablename__ = 'no_perecedero'
    id_producto = db.Column(db.Integer, db.ForeignKey('producto.id_producto'), primary_key=True)
    lote_fabricacion = db.Column(db.String(50))
    garantia_meses = db.Column(db.Integer, default=0)

class TelefonoProveedor(db.Model):
    __tablename__ = 'telefono_proveedor'
    id_proveedor = db.Column(db.Integer, db.ForeignKey('proveedor.id_proveedor'), primary_key=True)
    telefono = db.Column(db.String(20), primary_key=True)


# 3. MANEJO DE SESIÓN Y DCL


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

def get_session_dcl():
    """
    Devuelve una sesión DCL temporal. Usada para todas las operaciones DCL.
    ¡DEBEMOS CERRARLA MANUALMENTE (db_dcl.close())!
    """
    rol_usuario = current_user.rol
    rol_bind = 'gerente' if rol_usuario in ('admin', 'gerente') else rol_usuario
    
    if rol_bind in app.config['SQLALCHEMY_BINDS']:
        engine = db.get_engine(bind_key=rol_bind)
        Session = sessionmaker(bind=engine)
        return Session()
    else:
        return db.session


# 4. RUTAS DE AUTENTICACIÓN Y MENÚ


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('menu'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.rol == 'cliente':
            return redirect(url_for('mi_perfil'))
        if current_user.rol == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('menu'))
        
    error = None 
    if request.method == 'POST':
        

        email = request.form.get('email').strip()
        password = request.form.get('password').strip()

        
        user = Usuario.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            if user.rol == 'cliente':
                return redirect(url_for('mi_perfil'))
            if user.rol == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('menu'))
        else:
            error = 'Email o contraseña incorrectos.'
    
    return render_template('login.html', error=error)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        nombre = request.form.get('nombre')
        
        if Usuario.query.filter_by(email=email).first():
            return render_template('registro.html', error='Ese email ya está registrado.')

        db_dcl = None 
        
        try:

            # Obtenemos la sesión 'cliente' directamente.
            engine = db.get_engine(bind_key='cliente')
            Session = sessionmaker(bind=engine)
            db_dcl = Session()


            # 1. Crear el CLIENTE (con permisos DCL)
            nuevo_cliente = Cliente(
                nombre=nombre,
                email=email,
                telefono=None
            )
            db_dcl.add(nuevo_cliente)
            db_dcl.flush() 
            
            # 2. Crear el registro 'OCASIONAL'
            nuevo_ocasional = Ocasional(
                id_cliente=nuevo_cliente.id_cliente,
                ultima_fecha_visita=date.today()
            )
            db_dcl.add(nuevo_ocasional)
            db_dcl.commit() 

            
            nuevo_usuario = Usuario(
                email=email, 
                rol='cliente',
                id_cliente=nuevo_cliente.id_cliente
            )
            nuevo_usuario.set_password(password)
            
            db.session.add(nuevo_usuario)
            db.session.commit()
            
            flash('¡Cliente registrado con éxito! Por favor, inicia sesión.', 'success')
            return redirect(url_for('login'))
        
        except Exception as e:
            if db_dcl: 
                db_dcl.rollback()
            db.session.rollback() 
            return render_template('registro.html', error=f'Error inesperado: {e}')
        finally:
            if db_dcl: # Solo cerramos si la sesión DCL se creó 
                db_dcl.close()

    return render_template('registro.html')

@app.route('/menu')
@login_required 
def menu():
    if current_user.rol == 'cliente':
        return redirect(url_for('mi_perfil'))
    return render_template('menu.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

@app.route('/mi_perfil')
@login_required
def mi_perfil():
    if current_user.rol != 'cliente':
        flash('Esta sección es solo para clientes.', 'danger')
        return redirect(url_for('menu'))

    db_dcl = get_session_dcl()
    
    try:
        # Filtra por la app: Cliente.id_cliente == current_user.id_cliente
        cliente = db_dcl.query(Cliente).filter_by(id_cliente=current_user.id_cliente).first()
        
        if not cliente:
            flash('No se pudo encontrar tu registro de cliente.', 'danger')
            return redirect(url_for('logout'))

        # Consulta de ventas del cliente (filtrada por Python/App logic)
        ventas = db_dcl.query(Venta).filter_by(id_cliente=current_user.id_cliente).order_by(Venta.fecha_hora.desc()).all()
        
        return render_template('perfil_cliente.html', cliente=cliente, ventas=ventas)

    except Exception as e:
        db_dcl.rollback()
        return f"<h2>¡ERROR DE APLICACIÓN!</h2><p>{e}</p>", 500
    finally:
        db_dcl.close()


@app.route('/editar_perfil', methods=['GET', 'POST'])
@login_required
def editar_perfil():
    # solo los clientes puedan editar su perfil
    if current_user.rol != 'cliente':
        flash('Esta sección es solo para clientes.', 'danger')
        return redirect(url_for('menu'))

    db_dcl = get_session_dcl()
    
    
    # Buscamos al cliente usando el ID del usuario logueado
    cliente = db_dcl.query(Cliente).filter_by(id_cliente=current_user.id_cliente).first()
    
    if not cliente:
        flash('No se pudo encontrar tu registro de cliente.', 'danger')
        db_dcl.close() # Cerrar sesión antes de redirigir
        return redirect(url_for('logout'))

    if request.method == 'POST':
        
        cliente.nombre = request.form.get('nombre')
        cliente.telefono = request.form.get('telefono')
        cliente.calle = request.form.get('calle')
        cliente.numero_exterior = request.form.get('numero_exterior')
        cliente.colonia = request.form.get('colonia')
        cliente.codigo_postal = request.form.get('codigo_postal')
        
        
        db_dcl.commit()
        
        flash('¡Tu perfil se ha actualizado con éxito!', 'success')
        db_dcl.close()
        return redirect(url_for('mi_perfil'))


    db_dcl.close() # Cerrar sesión antes de redirigir
    return render_template('editar_perfil.html', cliente=cliente)

# 5. RUTAS DE OPERACIONES (POS, VENTAS)


@app.route('/pos', methods=['GET', 'POST'])
@login_required
def pos():
    if current_user.rol not in ('barista', 'gerente', 'admin'):
        flash('No tienes permiso para acceder al Punto de Venta.', 'danger')
        return redirect(url_for('menu'))

    db_dcl = get_session_dcl()

    try:
        if request.method == 'POST':
            id_cliente = request.form.get('id_cliente')
            monto_total = request.form.get('monto_total')
            
            if monto_total is None or float(monto_total) <= 0:
                flash('No se puede registrar una venta con total 0 o inválido.', 'warning')
                return redirect(url_for('pos'))

            nueva_venta = Venta(
                monto_total=monto_total,
                id_cliente=id_cliente,
                id_empleado=current_user.id_empleado
            )
            db_dcl.add(nueva_venta)
            db_dcl.flush() 
            
            detalles_agregados = 0
            for key, cantidad in request.form.items():
                if key.startswith('cantidad_') and int(cantidad) > 0:
                    id_producto = key.split('_')[1]
                    producto = db_dcl.query(Producto).get(id_producto)
                    
                    detalle = DetalleVenta(
                        id_venta=nueva_venta.id_venta,
                        id_producto=id_producto,
                        cantidad=int(cantidad),
                        precio_unitario=producto.precio_venta
                    )
                    db_dcl.add(detalle)
                    detalles_agregados += 1
            
            if detalles_agregados == 0:
                flash('No se seleccionó ningún producto.', 'warning')
                db_dcl.rollback()
                return redirect(url_for('pos'))

            db_dcl.commit()
            flash(f'¡Venta #{nueva_venta.id_venta} registrada con éxito!', 'success')
            return redirect(url_for('menu'))

        clientes = db_dcl.query(Cliente).all()
        productos = db_dcl.query(Producto).all()
        
        return render_template('pos.html', clientes=clientes, productos=productos)

    except errors.NotNullViolation as e:
        db_dcl.rollback()
        return f"<h2>¡ERROR DE DATOS!</h2><p>{e}</p>", 500
    except errors.InsufficientPrivilege as e:
        db_dcl.rollback()
        return f"<h2>¡ACCESO DENEGADO (DCL)!</h2><p>{e}</p>", 403
    except Exception as e:
        db_dcl.rollback() 
        return f"<h2>¡ERROR!</h2><p>{e}</p>", 500
    finally:
        db_dcl.close()

@app.route('/ventas')
@login_required
def ver_ventas():
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para ver el reporte de ventas.', 'danger')
        return redirect(url_for('menu'))

    db_dcl = get_session_dcl()

    try:
        filtro_empleado = request.args.get('empleado_id')
        ordenar_por = request.args.get('ordenar_por', 'recientes')
        
        query = db_dcl.query(Venta)

        if filtro_empleado and filtro_empleado.isdigit():
            query = query.filter(Venta.id_empleado == int(filtro_empleado))

        if ordenar_por == 'monto_desc':
            query = query.order_by(Venta.monto_total.desc())
        else:
            query = query.order_by(Venta.fecha_hora.desc())

        ventas = query.all()
        empleados = db_dcl.query(Empleado).all()

        return render_template('ventas.html', 
                               ventas=ventas, 
                               empleados=empleados,
                               filtro_empleado_actual=filtro_empleado,
                               ordenar_por_actual=ordenar_por)

    except errors.InsufficientPrivilege as e:
        db_dcl.rollback()
        return f"<h2>¡ACCESO DENEGADO (DCL)!</h2><p>{e}</p>", 403
    except Exception as e:
        db_dcl.rollback()
        return f"<h2>¡ERROR DE APLICACIÓN!</h2><p>{e}</p>", 500
    finally:
        db_dcl.close()

@app.route('/ventas/borrar/<int:id>')
@login_required
def borrar_venta(id):
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para borrar ventas.', 'danger')
        return redirect(url_for('ver_ventas'))

    db_dcl = get_session_dcl()
    
    try:
        venta = db_dcl.query(Venta).get(id)
        if not venta:
            flash('Venta no encontrada.', 'danger')
            return redirect(url_for('ver_ventas'))

        db_dcl.delete(venta)
        db_dcl.commit()
        flash(f'Venta #{venta.id_venta} borrada con éxito.', 'success')
    
    except errors.InsufficientPrivilege as e:
        db_dcl.rollback()
        flash(f'Error DCL al borrar la venta: {e}', 'danger')
    except Exception as e:
        db_dcl.rollback()
        flash(f'Error inesperado al borrar: {e}', 'danger')
    
    finally:
        db_dcl.close()
    
    return redirect(url_for('ver_ventas'))

@app.route('/venta/<int:id>')
@login_required
def ver_detalle_venta(id):
    if current_user.rol not in ('gerente', 'admin') and current_user.rol != 'cliente':
        flash('No tienes permisos para ver este detalle.', 'danger')
        return redirect(url_for('menu'))

    db_dcl = get_session_dcl()

    try:
        venta = db_dcl.query(Venta).get(id)
        
        if not venta:
            flash('Venta no encontrada.', 'danger')
            return redirect(url_for('ver_ventas'))
        
        # Un cliente solo puede ver sus propias ventas
        if current_user.rol == 'cliente' and venta.id_cliente != current_user.id_cliente:
             flash('No tienes permiso para ver esta venta.', 'danger')
             return redirect(url_for('mi_perfil'))

        return render_template('venta_detalle.html', venta=venta)

    except errors.InsufficientPrivilege as e:
        db_dcl.rollback()
        return f"<h2>¡ACCESO DENEGADO (DCL)!</h2><p>{e}</p>", 403
    except Exception as e:
        db_dcl.rollback()
        return f"<h2>¡ERROR DE APLICACIÓN!</h2><p>{e}</p>", 500
    finally:
        db_dcl.close()

# 6. RUTAS CRUD DE EMPLEADOS (GERENTE)


@app.route('/empleados')
@login_required
def ver_empleados():
    db_dcl = get_session_dcl()
    try:
        if current_user.rol == 'barista':
            lista_empleados = db_dcl.query(Empleado).with_entities(Empleado.nombre, Empleado.puesto).all()
            return render_template('empleados.html', 
                                   empleados=lista_empleados, 
                                   rol_usuario=current_user.rol)
        else:
            lista_empleados = db_dcl.query(Empleado).all()
            return render_template('empleados.html', 
                                   empleados=lista_empleados, 
                                   rol_usuario=current_user.rol)

    except errors.InsufficientPrivilege as e:
        db_dcl.rollback() 
        return f"<h2>¡ACCESO DENEGADO (DCL)!</h2><p>{e}</p>", 403
    except Exception as e:
        db_dcl.rollback() 
        return f"<h2>Error inesperado:</h2><p>{e}</p>", 500
    finally:
        db_dcl.close()

@app.route('/empleados/crear', methods=['GET', 'POST'])
@login_required
def crear_empleado():
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para contratar empleados.', 'danger')
        return redirect(url_for('ver_empleados'))
    
    db_dcl = get_session_dcl()
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        nombre = request.form.get('nombre')
        puesto = request.form.get('puesto')
        rol = request.form.get('rol')
        
        if db.session.query(Usuario).filter_by(email=email).first():
            flash(f'El email "{email}" ya está en uso.', 'danger')
            return render_template('empleado_crear.html')
            
        try:
            nuevo_empleado = Empleado(
                nombre=nombre,
                puesto=puesto,
                fecha_contratacion=date.today()
            )
            db_dcl.add(nuevo_empleado)
            db_dcl.commit()

            nuevo_usuario = Usuario(
                email=email, 
                rol=rol,
                id_empleado=nuevo_empleado.id_empleado
            )
            nuevo_usuario.set_password(password)
            
            db.session.add(nuevo_usuario)
            db.session.commit()
            
            flash(f'Empleado {nombre} contratado con éxito.', 'success')
            return redirect(url_for('ver_empleados'))
        
        except Exception as e:
            db_dcl.rollback()
            db.session.rollback()
            flash(f'Error al crear el empleado: {e}', 'danger')
        
        finally:
            db_dcl.close()

    return render_template('empleado_crear.html')

@app.route('/empleados/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_empleado(id):
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para editar empleados.', 'danger')
        return redirect(url_for('ver_empleados'))

    db_dcl = get_session_dcl()
    
    try:
        empleado = db_dcl.query(Empleado).get(id)
        if not empleado:
            flash('Empleado no encontrado.', 'danger')
            return redirect(url_for('ver_empleados'))

        if request.method == 'POST':
            empleado.nombre = request.form.get('nombre')
            empleado.puesto = request.form.get('puesto')
            empleado.fecha_contratacion = request.form.get('fecha_contratacion')
            
            db_dcl.commit()
            flash(f'Empleado {empleado.nombre} actualizado con éxito.', 'success')
            return redirect(url_for('ver_empleados'))
        
        return render_template('empleado_editar.html', empleado=empleado)

    except Exception as e:
        db_dcl.rollback()
        flash(f'Error DCL al editar: {e}', 'danger')
        return redirect(url_for('ver_empleados'))
    finally:
        db_dcl.close()

@app.route('/empleados/borrar/<int:id>')
@login_required
def borrar_empleado(id):
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para borrar empleados.', 'danger')
        return redirect(url_for('ver_empleados'))

    db_dcl = get_session_dcl()
    
    try:
        empleado = db_dcl.query(Empleado).get(id)
        if not empleado:
            flash('Empleado no encontrado.', 'danger')
            return redirect(url_for('ver_empleados'))

        usuario_asociado = db.session.query(Usuario).filter_by(id_empleado=id).first()
        if usuario_asociado:
            db.session.delete(usuario_asociado)
            db.session.commit()

        db_dcl.delete(empleado)
        db_dcl.commit()
        flash(f'Empleado {empleado.nombre} borrado con éxito.', 'success')
    
    except Exception as e:
        db_dcl.rollback()
        db.session.rollback()
        flash(f'Error DCL al borrar: {e}', 'danger')
    
    finally:
        db_dcl.close()
    
    return redirect(url_for('ver_empleados'))


# 7. RUTAS CRUD DE PRODUCTOS (GERENTE)


@app.route('/productos')
@login_required
def ver_productos():
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para ver los productos.', 'danger')
        return redirect(url_for('menu'))

    db_dcl = get_session_dcl()
    
    try:
        productos = db_dcl.query(Producto).all()
        return render_template('productos.html', productos=productos)

    except errors.InsufficientPrivilege as e:
        db_dcl.rollback()
        return f"<h2>¡ACCESO DENEGADO (DCL)!</h2><p>{e}</p>", 403
    except Exception as e:
        db_dcl.rollback()
        return f"<h2>¡ERROR DE APLICACIÓN!</h2><p>{e}</p>", 500
    finally:
        db_dcl.close()

@app.route('/productos/crear', methods=['GET', 'POST'])
@login_required
def crear_producto():
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para crear productos.', 'danger')
        return redirect(url_for('menu'))
    
    db_dcl = get_session_dcl()
    
    try:
        if request.method == 'POST':
            nuevo_producto = Producto(
                nombre=request.form.get('nombre'),
                precio_venta=request.form.get('precio_venta'),
                descripcion=request.form.get('descripcion')
            )
            
            proveedor_ids = request.form.getlist('proveedores')
            
            db_dcl.add(nuevo_producto)
            db_dcl.flush()

            if proveedor_ids:
                selected_proveedores = db_dcl.query(Proveedor).filter(Proveedor.id_proveedor.in_(proveedor_ids)).all()
                nuevo_producto.proveedores = selected_proveedores
            
            tipo_producto = request.form.get('tipo_producto')
            
            if tipo_producto == 'perecedero':
                fecha_caducidad = request.form.get('fecha_caducidad')
                if not fecha_caducidad:
                    flash('Error: La fecha de caducidad es obligatoria para productos perecederos.', 'danger')
                    proveedores = db_dcl.query(Proveedor).all()
                    return render_template('producto_form.html', producto=None, proveedores=proveedores)

                detalle_tipo = Perecedero(
                    id_producto=nuevo_producto.id_producto,
                    fecha_caducidad=fecha_caducidad,
                    condiciones_almacenamiento=request.form.get('condiciones_almacenamiento')
                )
            elif tipo_producto == 'no_perecedero':
                detalle_tipo = NoPerecedero(
                    id_producto=nuevo_producto.id_producto,
                    lote_fabricacion=request.form.get('lote_fabricacion'),
                    garantia_meses=int(request.form.get('garantia_meses') or 0)
                )
            
            if tipo_producto in ('perecedero', 'no_perecedero'):
                db_dcl.add(detalle_tipo)
            
            db_dcl.commit()
            
            flash(f'Producto "{nuevo_producto.nombre}" creado con éxito.', 'success')
            return redirect(url_for('ver_productos'))
        
        proveedores = db_dcl.query(Proveedor).all()
        return render_template('producto_form.html', producto=None, proveedores=proveedores)

    except errors.CheckViolation as e:
        db_dcl.rollback()
        if 'chk_fecha_caducidad' in str(e):
            flash('Error: No se pueden añadir productos o alimentos caducados.', 'danger')
            proveedores = db_dcl.query(Proveedor).all()
            return render_template('producto_form.html', producto=None, proveedores=proveedores)
        else:
            flash(f'Error de base de datos: {e}', 'danger')
            return redirect(url_for('ver_productos'))
    except Exception as e:
        db_dcl.rollback()
        flash(f'Error al crear el producto: {e}', 'danger')
        return redirect(url_for('ver_productos'))
    finally:
        db_dcl.close()

@app.route('/productos/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_producto(id):
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para editar productos.', 'danger')
        return redirect(url_for('ver_productos'))
    
    db_dcl = get_session_dcl()
    
    try:
        producto = db_dcl.query(Producto).get(id)
        if not producto:
            flash('Producto no encontrado.', 'danger')
            return redirect(url_for('ver_productos'))

        if request.method == 'POST':
            producto.nombre = request.form.get('nombre')
            producto.precio_venta = request.form.get('precio_venta')
            producto.descripcion = request.form.get('descripcion')
            
            proveedor_ids = request.form.getlist('proveedores')
            selected_proveedores = db_dcl.query(Proveedor).filter(Proveedor.id_proveedor.in_(proveedor_ids)).all()
            producto.proveedores = selected_proveedores
            
            tipo_nuevo = request.form.get('tipo_producto')
            
            if tipo_nuevo == 'perecedero':
                fecha_caducidad = request.form.get('fecha_caducidad')
                if not fecha_caducidad:
                    flash('Error: La fecha de caducidad es obligatoria para productos perecederos.', 'danger')
                    proveedores = db_dcl.query(Proveedor).all()
                    return render_template('producto_form.html', producto=producto, proveedores=proveedores)
                    
                if producto.no_perecedero:
                    db_dcl.delete(producto.no_perecedero)
                if not producto.perecedero:
                    producto.perecedero = Perecedero(id_producto=producto.id_producto)
                
                producto.perecedero.fecha_caducidad = fecha_caducidad
                producto.perecedero.condiciones_almacenamiento = request.form.get('condiciones_almacenamiento')

            elif tipo_nuevo == 'no_perecedero':
                if producto.perecedero:
                    db_dcl.delete(producto.perecedero)
                if not producto.no_perecedero:
                    producto.no_perecedero = NoPerecedero(id_producto=producto.id_producto)
                
                producto.no_perecedero.lote_fabricacion = request.form.get('lote_fabricacion')
                producto.no_perecedero.garantia_meses = int(request.form.get('garantia_meses') or 0)
            
            else:
                if producto.perecedero:
                    db_dcl.delete(producto.perecedero)
                if producto.no_perecedero:
                    db_dcl.delete(producto.no_perecedero)
            
            db_dcl.commit()
            flash(f'Producto "{producto.nombre}" actualizado con éxito.', 'success')
            return redirect(url_for('ver_productos'))
        
        proveedores = db_dcl.query(Proveedor).all()
        return render_template('producto_form.html', producto=producto, proveedores=proveedores)

    except errors.CheckViolation as e:
        db_dcl.rollback()
        if 'chk_fecha_caducidad' in str(e):
            flash('Error: No se pueden añadir productos o alimentos caducados.', 'danger')
            proveedores = db_dcl.query(Proveedor).all()
            return render_template('producto_form.html', producto=producto, proveedores=proveedores)
        else:
            flash(f'Error de base de datos: {e}', 'danger')
            return redirect(url_for('ver_productos'))
    except Exception as e:
        db_dcl.rollback()
        flash(f'Error al editar el producto: {e}', 'danger')
        return redirect(url_for('ver_productos'))
    finally:
        db_dcl.close()

@app.route('/productos/borrar/<int:id>')
@login_required
def borrar_producto(id):
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para borrar productos.', 'danger')
        return redirect(url_for('ver_productos'))
    
    db_dcl = get_session_dcl()
    
    try:
        producto = db_dcl.query(Producto).get(id)
        if producto:
            db_dcl.delete(producto)
            db_dcl.commit()
            flash(f'Producto "{producto.nombre}" borrado con éxito.', 'success')
        else:
            flash('Producto no encontrado.', 'warning')

    except exc.IntegrityError as e:
        db_dcl.rollback()
        flash(f'Error: No se puede borrar el producto porque está usado en ventas (Error de integridad).', 'danger')
    except Exception as e:
        db_dcl.rollback()
        flash(f'Error al borrar el producto: {e}', 'danger')
    finally:
        db_dcl.close()
    
    return redirect(url_for('ver_productos'))


# 8. RUTAS CRUD DE PROVEEDORES (GERENTE)


@app.route('/proveedores')
@login_required
def ver_proveedores():
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para ver los proveedores.', 'danger')
        return redirect(url_for('menu'))

    db_dcl = get_session_dcl()
    
    try:
        proveedores = db_dcl.query(Proveedor).all()
        return render_template('proveedores.html', proveedores=proveedores)

    except errors.InsufficientPrivilege as e:
        db_dcl.rollback()
        return f"<h2>¡ACCESO DENEGADO (DCL)!</h2><p>{e}</p>", 403
    except Exception as e:
        db_dcl.rollback()
        return f"<h2>¡ERROR DE APLICACIÓN!</h2><p>{e}</p>", 500
    finally:
        db_dcl.close()

@app.route('/proveedores/crear', methods=['GET', 'POST'])
@login_required
def crear_proveedor():
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para crear proveedores.', 'danger')
        return redirect(url_for('ver_proveedores'))
    
    db_dcl = get_session_dcl()
    
    try:
        if request.method == 'POST':
            nombre = request.form.get('nombre')
            email = request.form.get('email')
            
            existente = db_dcl.query(Proveedor).filter_by(email=email).first()
            if existente:
                flash(f'Error: El email "{email}" ya está registrado.', 'danger')
                return render_template('proveedor_form.html', proveedor=None)

            nuevo_proveedor = Proveedor(
                nombre=nombre,
                email=email
            )
            
            db_dcl.add(nuevo_proveedor)
            db_dcl.commit()
            
            flash(f'Proveedor "{nombre}" creado con éxito.', 'success')
            return redirect(url_for('ver_proveedores'))
        
        return render_template('proveedor_form.html', proveedor=None)

    except Exception as e:
        db_dcl.rollback()
        flash(f'Error al crear el proveedor: {e}', 'danger')
        return redirect(url_for('ver_proveedores'))
    finally:
        db_dcl.close()

@app.route('/proveedores/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_proveedor(id):
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para editar proveedores.', 'danger')
        return redirect(url_for('ver_proveedores'))
    
    db_dcl = get_session_dcl()
    
    try:
        proveedor = db_dcl.query(Proveedor).get(id)
        if not proveedor:
            flash('Proveedor no encontrado.', 'danger')
            return redirect(url_for('ver_proveedores'))

        if request.method == 'POST':
            proveedor.nombre = request.form.get('nombre')
            proveedor.email = request.form.get('email')
            
            db_dcl.commit()
            
            flash(f'Proveedor "{proveedor.nombre}" actualizado con éxito.', 'success')
            return redirect(url_for('ver_proveedores'))
        
        return render_template('proveedor_form.html', proveedor=proveedor)

    except Exception as e:
        db_dcl.rollback()
        flash(f'Error al editar el proveedor: {e}', 'danger')
        return redirect(url_for('ver_proveedores'))
    finally:
        db_dcl.close()

@app.route('/proveedores/borrar/<int:id>')
@login_required
def borrar_proveedor(id):
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos para borrar proveedores.', 'danger')
        return redirect(url_for('ver_proveedores'))
    
    db_dcl = get_session_dcl()
    
    try:
        proveedor = db_dcl.query(Proveedor).get(id)
        if proveedor:
            db_dcl.delete(proveedor)
            db_dcl.commit()
            flash(f'Proveedor "{proveedor.nombre}" borrado con éxito.', 'success')
        else:
            flash('Proveedor no encontrado.', 'warning')
            
    except exc.IntegrityError as e:
        db_dcl.rollback()
        flash(f'Error: No se puede borrar el proveedor porque está en uso (Error de integridad).', 'danger')
    except Exception as e:
        db_dcl.rollback()
        flash(f'Error al borrar el proveedor: {e}', 'danger')
    finally:
        db_dcl.close()
    
    return redirect(url_for('ver_proveedores'))

@app.route('/proveedores/agregar_telefono/<int:id>', methods=['POST'])
@login_required
def agregar_telefono_proveedor(id):
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos.', 'danger')
        return redirect(url_for('ver_proveedores'))
    
    db_dcl = get_session_dcl()
    try:
        telefono = request.form.get('telefono')
        if not telefono:
            flash('El número de teléfono no puede estar vacío.', 'warning')
            return redirect(url_for('editar_proveedor', id=id))
            
        nuevo_telefono = TelefonoProveedor(
            id_proveedor=id,
            telefono=telefono
        )
        db_dcl.add(nuevo_telefono)
        db_dcl.commit()
        flash('Teléfono añadido con éxito.', 'success')
        
    except exc.IntegrityError:
        db_dcl.rollback()
        flash('Ese número de teléfono ya está registrado para este proveedor.', 'danger')
    except Exception as e:
        db_dcl.rollback()
        flash(f'Error al añadir teléfono: {e}', 'danger')
    finally:
        db_dcl.close()
        
    return redirect(url_for('editar_proveedor', id=id))

@app.route('/proveedores/borrar_telefono/<int:id>/<string:telefono>')
@login_required
def borrar_telefono_proveedor(id, telefono):
    if current_user.rol not in ('gerente', 'admin'):
        flash('No tienes permisos.', 'danger')
        return redirect(url_for('ver_proveedores'))
        
    db_dcl = get_session_dcl()
    try:
        telefono_limpio = telefono.replace('%20', ' ')
        telefono_obj = db_dcl.query(TelefonoProveedor).get((id, telefono_limpio))
        if telefono_obj:
            db_dcl.delete(telefono_obj)
            db_dcl.commit()
            flash('Teléfono borrado con éxito.', 'success')
        else:
            flash('Teléfono no encontrado.', 'warning')
            
    except Exception as e:
        db_dcl.rollback()
        flash(f'Error al borrar teléfono: {e}', 'danger')
    finally:
        db_dcl.close()
        
    return redirect(url_for('editar_proveedor', id=id))

# 9. RUTAS CRUD DE CLIENTES (GERENTE Y BARISTA)


@app.route('/clientes')
@login_required
def ver_clientes():
    if current_user.rol not in ('barista', 'gerente', 'admin'):
        flash('No tienes permisos para ver los clientes.', 'danger')
        return redirect(url_for('menu'))

    db_dcl = get_session_dcl()
    
    try:
        clientes = db_dcl.query(Cliente).outerjoin(Frecuente).all()
        return render_template('clientes.html', clientes=clientes)

    except errors.InsufficientPrivilege as e:
        db_dcl.rollback()
        return f"<h2>¡ACCESO DENEGADO (DCL)!</h2><p>{e}</p>", 403
    except Exception as e:
        db_dcl.rollback()
        return f"<h2>¡ERROR DE APLICACIÓN!</h2><p>{e}</p>", 500
    finally:
        db_dcl.close()

@app.route('/clientes/crear', methods=['GET', 'POST'])
@login_required
def crear_cliente():
    if current_user.rol not in ('barista', 'gerente', 'admin'):
        flash('No tienes permisos para crear clientes.', 'danger')
        return redirect(url_for('menu'))
    
    db_dcl = get_session_dcl()
    
    try:
        if request.method == 'POST':
            
            nombre = request.form.get('nombre')
            email = request.form.get('email')
            telefono = request.form.get('telefono')
            tipo_cliente = request.form.get('tipo_cliente')
            puntos = request.form.get('puntos_acumulados', 0)
            
            calle = request.form.get('calle')
            numero_exterior = request.form.get('numero_exterior')
            colonia = request.form.get('colonia')
            codigo_postal = request.form.get('codigo_postal')
            

            existente = db_dcl.query(Cliente).filter_by(email=email).first()
            if existente:
                flash(f'Error: El email "{email}" ya está registrado.', 'danger')
                return render_template('cliente_form.html', cliente=None)

           
            nuevo_cliente = Cliente(
                nombre=nombre,
                email=email,
                telefono=telefono,
                calle=calle,
                numero_exterior=numero_exterior,
                colonia=colonia,
                codigo_postal=codigo_postal
            )
            
            db_dcl.add(nuevo_cliente)
            db_dcl.flush()

            if tipo_cliente == 'frecuente':
                nuevo_frecuente = Frecuente(
                    id_cliente=nuevo_cliente.id_cliente,
                    puntos_acumulados=int(puntos)
                )
                db_dcl.add(nuevo_frecuente)
            else:
                nuevo_ocasional = Ocasional(
                    id_cliente=nuevo_cliente.id_cliente,
                    ultima_fecha_visita=date.today()
                )
                db_dcl.add(nuevo_ocasional)
            
            db_dcl.commit()
            flash(f'Cliente "{nombre}" creado con éxito.', 'success')
            return redirect(url_for('ver_clientes'))
        
        return render_template('cliente_form.html', cliente=None)

    except Exception as e:
        db_dcl.rollback()
        flash(f'Error al crear el cliente: {e}', 'danger')
        return redirect(url_for('ver_clientes'))
    finally:
        db_dcl.close()

@app.route('/clientes/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_cliente(id):
    if current_user.rol not in ('barista', 'gerente', 'admin'):
        flash('No tienes permisos para editar clientes.', 'danger')
        return redirect(url_for('ver_clientes'))
    
    db_dcl = get_session_dcl()
    
    try:
        cliente = db_dcl.query(Cliente).get(id)
        if not cliente:
            flash('Cliente no encontrado.', 'danger')
            return redirect(url_for('ver_clientes'))

        if request.method == 'POST':
            
            cliente.nombre = request.form.get('nombre')
            cliente.email = request.form.get('email')
            cliente.telefono = request.form.get('telefono')
            
            cliente.calle = request.form.get('calle')
            cliente.numero_exterior = request.form.get('numero_exterior')
            cliente.colonia = request.form.get('colonia')
            cliente.codigo_postal = request.form.get('codigo_postal')
            # --- FIN DE ACTUALIZACIÓN ---
            
            tipo_nuevo = request.form.get('tipo_cliente')
            puntos_nuevos = request.form.get('puntos_acumulados', 0)
            
            if tipo_nuevo == 'frecuente':
                if cliente.ocasional:
                    db_dcl.delete(cliente.ocasional)
                
                if not cliente.frecuente:
                    nuevo_frecuente = Frecuente(id_cliente=cliente.id_cliente)
                    db_dcl.add(nuevo_frecuente)
                    db_dcl.flush()
                
                cliente.frecuente.puntos_acumulados = int(puntos_nuevos)
            
            else:
                if cliente.frecuente:
                    db_dcl.delete(cliente.frecuente)
                
                if not cliente.ocasional:
                    nuevo_ocasional = Ocasional(id_cliente=cliente.id_cliente)
                    db_dcl.add(nuevo_ocasional)
            
            db_dcl.commit()
            flash(f'Cliente "{cliente.nombre}" actualizado con éxito.', 'success')
            return redirect(url_for('ver_clientes'))
        
        return render_template('cliente_form.html', cliente=cliente)

    except Exception as e:
        db_dcl.rollback()
        flash(f'Error al editar el cliente: {e}', 'danger')
        return redirect(url_for('ver_clientes'))
    finally:
        db_dcl.close()

@app.route('/clientes/borrar/<int:id>')
@login_required
def borrar_cliente(id):
    if current_user.rol not in ('barista', 'gerente', 'admin'):
        flash('No tienes permisos para borrar clientes.', 'danger')
        return redirect(url_for('ver_clientes'))
    
    db_dcl = get_session_dcl()
    
    try:
        cliente = db_dcl.query(Cliente).get(id)
        if cliente:
            db_dcl.delete(cliente)
            db_dcl.commit()
            flash(f'Cliente "{cliente.nombre}" borrado con éxito.', 'success')
        else:
            flash('Cliente no encontrado.', 'warning')
            
    except exc.IntegrityError as e:
        db_dcl.rollback()
        flash(f'Error: No se puede borrar el cliente porque tiene ventas asociadas (Error de integridad).', 'danger')
    except Exception as e:
        db_dcl.rollback()
        flash(f'Error al borrar el cliente: {e}', 'danger')
    finally:
        db_dcl.close()
    
    return redirect(url_for('ver_clientes'))



# 10. RUTAS DE ADMINISTRADOR


@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    
    try:
        num_usuarios = db.session.query(Usuario).count()
        
        # Usamos la sesión DCL (gerente) 
        db_dcl = get_session_dcl()
        num_productos = db_dcl.query(Producto).count()
        num_clientes = db_dcl.query(Cliente).count()
        num_ventas = db_dcl.query(Venta).count()
        num_proveedores = db_dcl.query(Proveedor).count()
        num_empleados = db_dcl.query(Empleado).count()
        
        stats = {
            'usuarios': num_usuarios,
            'productos': num_productos,
            'clientes': num_clientes,
            'ventas': num_ventas,
            'proveedores': num_proveedores,
            'empleados': num_empleados
        }
    except Exception as e:
        flash(f'Error al cargar estadísticas: {e}', 'danger')
        stats = {}
    finally:
        if 'db_dcl' in locals() and db_dcl:
            db_dcl.close()
            
    return render_template('admin_dashboard.html', stats=stats)


@app.route('/admin/usuarios')
@login_required
@admin_required
def admin_ver_usuarios():
    # La tabla Usuario se maneja con la sesión ADMIN 
    try:
        usuarios = db.session.query(Usuario).all()
        return render_template('admin_usuarios.html', usuarios=usuarios)
    except Exception as e:
        flash(f'Error al cargar usuarios: {e}', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/usuarios/borrar/<int:id>')
@login_required
@admin_required
def admin_borrar_usuario(id):
    # ¡PELIGRO! Borrar un usuario puede dejar registros huérfanos.
    if id == current_user.id:
        flash('No puedes borrarte a ti mismo.', 'danger')
        return redirect(url_for('admin_ver_usuarios'))

    try:
        # Usamos la sesión ADMIN 
        usuario = db.session.query(Usuario).get(id)
        if usuario:
           
            email = usuario.email
            db.session.delete(usuario)
            db.session.commit()
            flash(f'Usuario {email} borrado con éxito.', 'success')
        else:
            flash('Usuario no encontrado.', 'warning')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al borrar el usuario: {e}', 'danger')
    
    return redirect(url_for('admin_ver_usuarios'))




# -----------------------------------------------------------------
# 11. PUNTO DE ENTRADA DE LA APLICACIÓN
# -----------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)