
/* 1. DEFINICIÓN DE SECUENCIAS */

CREATE SEQUENCE empleado_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE cliente_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE proveedor_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE producto_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE venta_id_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE usuario_id_seq START WITH 1 INCREMENT BY 1; 


/* 2. DEFINICIÓN DE TABLAS PRINCIPALES */

CREATE TABLE EMPLEADO (
   id_empleado INT NOT NULL DEFAULT nextval('empleado_id_seq'),
   nombre VARCHAR(100) NOT NULL,
   puesto VARCHAR(50) NOT NULL,
   fecha_contratacion DATE NOT NULL,
   CONSTRAINT pk_empleado PRIMARY KEY (id_empleado),
   CONSTRAINT chk_fecha_contratacion CHECK (fecha_contratacion <= CURRENT_DATE)
);

CREATE TABLE CLIENTE (
   id_cliente INT NOT NULL DEFAULT nextval('cliente_id_seq'),
   nombre VARCHAR(100) NOT NULL,
   email VARCHAR(100) NOT NULL,
   telefono VARCHAR(20),
   
   calle VARCHAR(100),
   numero_exterior VARCHAR(20),
   colonia VARCHAR(100),
   codigo_postal VARCHAR(10),
   CONSTRAINT pk_cliente PRIMARY KEY (id_cliente),
   CONSTRAINT uq_cliente_email UNIQUE (email),
   CONSTRAINT chk_email_cliente CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
   CONSTRAINT chk_telefono_cliente CHECK (telefono IS NULL OR telefono ~ '^[0-9()+\- ]+$')
);

/* --- TABLA USUARIO --- */
CREATE TABLE USUARIO (
   id_usuario INT NOT NULL DEFAULT nextval('usuario_id_seq'),
   email VARCHAR(100) NOT NULL,
   password_hash VARCHAR(255) NOT NULL,
   rol VARCHAR(50) NOT NULL,
   id_cliente INT,
   id_empleado INT,
   CONSTRAINT pk_usuario PRIMARY KEY (id_usuario),
   CONSTRAINT uq_usuario_email UNIQUE (email),
   CONSTRAINT fk_usuario_cliente FOREIGN KEY (id_cliente) REFERENCES CLIENTE(id_cliente) ON DELETE SET NULL,
   CONSTRAINT fk_usuario_empleado FOREIGN KEY (id_empleado) REFERENCES EMPLEADO(id_empleado) ON DELETE SET NULL
);

CREATE TABLE PROVEEDOR (
   id_proveedor INT NOT NULL DEFAULT nextval('proveedor_id_seq'),
   nombre VARCHAR(100) NOT NULL,
   email VARCHAR(100) NOT NULL,
   CONSTRAINT pk_proveedor PRIMARY KEY (id_proveedor),
   CONSTRAINT uq_proveedor_email UNIQUE (email)
);

CREATE TABLE PRODUCTO (
   id_producto INT NOT NULL DEFAULT nextval('producto_id_seq'),
   nombre VARCHAR(100) NOT NULL,
   descripcion TEXT,
   precio_venta DECIMAL(10, 2) NOT NULL,
   CONSTRAINT pk_producto PRIMARY KEY (id_producto),
   CONSTRAINT chk_precio_venta_positivo CHECK (precio_venta > 0)
);

-- Asignar secuencias a sus tablas
ALTER SEQUENCE empleado_id_seq OWNED BY EMPLEADO.id_empleado;
ALTER SEQUENCE cliente_id_seq OWNED BY CLIENTE.id_cliente;
ALTER SEQUENCE proveedor_id_seq OWNED BY PROVEEDOR.id_proveedor;
ALTER SEQUENCE producto_id_seq OWNED BY PRODUCTO.id_producto;
ALTER SEQUENCE usuario_id_seq OWNED BY USUARIO.id_usuario; 


/* 3. DEFINICIÓN DE TABLAS (TIPOS Y RELACIONES) */


-- Tipos de Cliente
CREATE TABLE FRECUENTE (
   id_cliente INT NOT NULL,
   puntos_acumulados INT NOT NULL DEFAULT 0,
   fecha_registro_vip DATE NOT NULL,
   CONSTRAINT pk_frecuente PRIMARY KEY (id_cliente),
   CONSTRAINT fk_frecuente_cliente FOREIGN KEY (id_cliente) REFERENCES CLIENTE(id_cliente) ON DELETE CASCADE ON UPDATE CASCADE,
   CONSTRAINT chk_puntos_positivos CHECK (puntos_acumulados >= 0)
);

CREATE TABLE OCASIONAL (
   id_cliente INT NOT NULL,
   ultima_fecha_visita DATE,
   CONSTRAINT pk_ocasional PRIMARY KEY (id_cliente),
   CONSTRAINT fk_ocasional_cliente FOREIGN KEY (id_cliente) REFERENCES CLIENTE(id_cliente) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Relación Proveedor
CREATE TABLE TELEFONO_PROVEEDOR (
   id_proveedor INT NOT NULL,
   telefono VARCHAR(20) NOT NULL,
   CONSTRAINT pk_telefono_proveedor PRIMARY KEY (id_proveedor, telefono),
   CONSTRAINT fk_telefono_proveedor FOREIGN KEY (id_proveedor) REFERENCES PROVEEDOR(id_proveedor) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Tipos de Producto
CREATE TABLE PERECEDERO (
   id_producto INT NOT NULL,
   fecha_caducidad DATE NOT NULL,
   condiciones_almacenamiento VARCHAR(255),
   CONSTRAINT pk_perecedero PRIMARY KEY (id_producto),
   CONSTRAINT fk_perecedero_producto FOREIGN KEY (id_producto) REFERENCES PRODUCTO(id_producto) ON DELETE CASCADE ON UPDATE CASCADE,
   CONSTRAINT chk_fecha_caducidad CHECK (fecha_caducidad > CURRENT_DATE)
);

CREATE TABLE NO_PERECEDERO (
   id_producto INT NOT NULL,
   lote_fabricacion VARCHAR(50),
   garantia_meses INT DEFAULT 0,
   CONSTRAINT pk_no_perecedero PRIMARY KEY (id_producto),
   CONSTRAINT fk_no_perecedero_producto FOREIGN KEY (id_producto) REFERENCES PRODUCTO(id_producto) ON DELETE CASCADE ON UPDATE CASCADE,
   CONSTRAINT chk_garantia_positiva CHECK (garantia_meses >= 0)
);

-- Tabla de Asociación (Muchos a Muchos)
CREATE TABLE PROVEEDOR_PRODUCTO (
   id_proveedor INT NOT NULL,
   id_producto INT NOT NULL,
   CONSTRAINT pk_proveedor_producto PRIMARY KEY (id_proveedor, id_producto),
   CONSTRAINT fk_pp_proveedor FOREIGN KEY (id_proveedor) REFERENCES PROVEEDOR(id_proveedor) ON DELETE RESTRICT ON UPDATE CASCADE,
   CONSTRAINT fk_pp_producto FOREIGN KEY (id_producto) REFERENCES PRODUCTO(id_producto) ON DELETE RESTRICT ON UPDATE CASCADE
);


/* 4. DEFINICIÓN DE TABLAS DE TRANSACCIONES */


CREATE TABLE VENTA (
   id_venta INT NOT NULL DEFAULT nextval('venta_id_seq'),
   fecha_hora TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
   monto_total DECIMAL(10, 2) NOT NULL,
   id_cliente INT NOT NULL,
   id_empleado INT NOT NULL,
   CONSTRAINT pk_venta PRIMARY KEY (id_venta),
   CONSTRAINT fk_venta_cliente FOREIGN KEY (id_cliente) REFERENCES CLIENTE(id_cliente) ON DELETE RESTRICT ON UPDATE CASCADE,
   CONSTRAINT fk_venta_empleado FOREIGN KEY (id_empleado) REFERENCES EMPLEADO(id_empleado) ON DELETE RESTRICT ON UPDATE CASCADE,
   CONSTRAINT chk_monto_total_positivo CHECK (monto_total >= 0)
);

ALTER SEQUENCE venta_id_seq OWNED BY VENTA.id_venta;

CREATE TABLE DETALLE_VENTA (
   id_venta INT NOT NULL,
   id_producto INT NOT NULL,
   cantidad INT NOT NULL,
   precio_unitario DECIMAL(10, 2) NOT NULL,
   CONSTRAINT pk_detalle_venta PRIMARY KEY (id_venta, id_producto),
   CONSTRAINT fk_dv_venta FOREIGN KEY (id_venta) REFERENCES VENTA(id_venta) ON DELETE CASCADE ON UPDATE CASCADE,
   CONSTRAINT fk_dv_producto FOREIGN KEY (id_producto) REFERENCES PRODUCTO(id_producto) ON DELETE RESTRICT ON UPDATE CASCADE,
   CONSTRAINT chk_cantidad_positiva CHECK (cantidad > 0),
   CONSTRAINT chk_precio_unitario_positivo CHECK (precio_unitario > 0)
);


/* 5. CREACIÓN DE ROLES Y PERMISOS (DCL) */


-- --- 1. CREACIÓN DE ROLES (USUARIOS) ---
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_cliente') THEN
        CREATE ROLE app_cliente LOGIN PASSWORD 'cliente_pass';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_barista') THEN
        CREATE ROLE app_barista LOGIN PASSWORD 'barista_pass';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_gerente') THEN
        CREATE ROLE app_gerente LOGIN PASSWORD 'gerente_pass';
    END IF;
END$$;



/* --- 2. PERMISOS PARA 'app_cliente' --- */
GRANT USAGE ON SEQUENCE cliente_id_seq, usuario_id_seq TO app_cliente;
GRANT INSERT, SELECT, UPDATE ON TABLE CLIENTE TO app_cliente; /* <-- ESTA LÍNEA ES LA CLAVE */
GRANT INSERT, SELECT ON TABLE OCASIONAL TO app_cliente;
GRANT SELECT ON TABLE FRECUENTE TO app_cliente;
GRANT SELECT ON TABLE VENTA, DETALLE_VENTA, PRODUCTO, EMPLEADO TO app_cliente;
GRANT INSERT, SELECT ON TABLE USUARIO TO app_cliente;

-- --- 3. PERMISOS PARA 'app_barista' ---
GRANT SELECT ON TABLE PRODUCTO, CLIENTE, FRECUENTE, OCASIONAL TO app_barista;
GRANT USAGE ON SEQUENCE venta_id_seq, cliente_id_seq TO app_barista;
GRANT INSERT ON TABLE VENTA, DETALLE_VENTA TO app_barista;
GRANT INSERT, SELECT, UPDATE, DELETE ON TABLE CLIENTE, FRECUENTE, OCASIONAL TO app_barista;
GRANT SELECT (nombre, puesto) ON TABLE EMPLEADO TO app_barista;
GRANT SELECT ON TABLE USUARIO TO app_barista;


-- --- 4. PERMISOS PARA 'app_gerente' ---
GRANT app_barista TO app_gerente;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_gerente;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO app_gerente;