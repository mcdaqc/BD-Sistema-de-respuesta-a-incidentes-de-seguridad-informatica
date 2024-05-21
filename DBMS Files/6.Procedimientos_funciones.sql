
-----------------------------------------------
------------------ FUNCIONES ------------------
-----------------------------------------------

-- Función para obtener el ID de un incidente a partir de su descripción
CREATE OR REPLACE FUNCTION id_incidente(descripcion_incidente IN VARCHAR2) RETURN CHAR IS
    incidente_id CHAR(10);
    CURSOR incidente_cursor IS
        SELECT INCIDENTE_ID FROM INCIDENTE WHERE DESCRIPCION = descripcion_incidente;
BEGIN
    OPEN incidente_cursor;
    FETCH incidente_cursor INTO incidente_id;

    IF incidente_cursor%NOTFOUND THEN
        incidente_id := NULL;
    END IF;
    CLOSE incidente_cursor;

    RETURN incidente_id;
END id_incidente;
/


--PARA PROBAR
SET SERVEROUTPUT ON
DECLARE
    incidente_id CHAR(10);
BEGIN
    incidente_id := id_incidente('Malware detectado');
    IF incidente_id IS NOT NULL THEN
        DBMS_OUTPUT.PUT_LINE('ID del incidente: ' || incidente_id);
    ELSE
        DBMS_OUTPUT.PUT_LINE('No se encontró ningún incidente con esa descripción.');
    END IF;
END;
/









-----------------------------------------------------
------------------ PROCEDIMIEMNTOS ------------------
-----------------------------------------------------


------------------------------------------------------------------
-- Procedimiento para registrar un nuevo incidente
------------------------------------------------------------------

CREATE OR REPLACE PROCEDURE registrar_incidente(
    p_incidente_id IN CHAR,
    descripcion_incidente IN VARCHAR2,
    nombre_usuario IN VARCHAR2,
    apellido_usuario IN VARCHAR2,
    nombre_activo IN VARCHAR2,
    direccion_mac IN VARCHAR2,
    gravedad IN VARCHAR2,
    estado IN VARCHAR2
) IS
    usuario_id CHAR(10);
    activo_id CHAR(10);

    CURSOR usuario_cursor IS
        SELECT USUARIO_ID FROM USUARIO
        WHERE NOMBRE_USUARIO = nombre_usuario AND APELLIDO_USUARIO = apellido_usuario;

    CURSOR activo_cursor IS
        SELECT ACTIVO_ID FROM ACTIVO
        WHERE NOMBRE_ACTIVO = nombre_activo AND DIRECCION_MAC = direccion_mac;

    v_incidente_existente CHAR(10);
BEGIN
    -- Verifica si el usuario existe
    BEGIN
        OPEN usuario_cursor;
        FETCH usuario_cursor INTO usuario_id;
        CLOSE usuario_cursor;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            DBMS_OUTPUT.PUT_LINE('El usuario con nombre ' || nombre_usuario || ' y apellido ' || apellido_usuario || ' no existe.');
            RETURN;
    END;

    -- Verifica si el activo existe
    BEGIN
        OPEN activo_cursor;
        FETCH activo_cursor INTO activo_id;
        CLOSE activo_cursor;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            DBMS_OUTPUT.PUT_LINE('El activo con nombre ' || nombre_activo || ' y dirección MAC ' || direccion_mac || ' no existe.');
            RETURN;
    END;

    -- Verifica si el incidente ya existe
    v_incidente_existente := obtener_id_incidente(descripcion_incidente);

    IF v_incidente_existente IS NOT NULL THEN
        DBMS_OUTPUT.PUT_LINE('El incidente ya existe con ID: ' || v_incidente_existente);
        RETURN;
    END IF;

    -- Insercion del nuevo incidente
    INSERT INTO INCIDENTE (INCIDENTE_ID, USUARIO_ID, ACTIVO_ID, DESCRIPCION, FECHA, GRAVEDAD, ESTADO)
    VALUES (p_incidente_id, usuario_id, activo_id, descripcion_incidente, SYSDATE, gravedad, estado);

    DBMS_OUTPUT.PUT_LINE('Nuevo incidente registrado con ID: ' || p_incidente_id);

END;
/


BEGIN
    -- Llamar al procedimiento para registrar un nuevo incidente
    registrar_incidente(
        p_incidente_id => 'I322',
        descripcion_incidente => 'Incidente de prueba',
        nombre_usuario => 'Juan',
        apellido_usuario => 'Pico',
        nombre_activo => 'Servidor1',
        direccion_mac => '00:1A:2B:3C:4D:5E',
        gravedad => 'Alta',
        estado => 'Abierto'
    );
END;
/




------------------------------------------------------------------
-- Procedimiento para mostrar los detalles de un incidente, 
-- el usuario que los reporto e informacion del activo afectado
------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE mostrar_detalles_usuario_incidente(
    p_descripcion_incidente IN VARCHAR2
) IS
    v_incidente_id INCIDENTE.INCIDENTE_ID%TYPE;
    v_usuario_id USUARIO.USUARIO_ID%TYPE;
    v_nombre_usuario USUARIO.NOMBRE_USUARIO%TYPE;
    v_apellido_usuario USUARIO.APELLIDO_USUARIO%TYPE;
    v_nombre_activo ACTIVO.NOMBRE_ACTIVO%TYPE;
    v_direccion_ip ACTIVO.DIRECCION_IP%TYPE;
    v_direccion_mac ACTIVO.DIRECCION_MAC%TYPE;

    CURSOR incidente_cursor IS
        SELECT I.INCIDENTE_ID, U.USUARIO_ID, U.NOMBRE_USUARIO, U.APELLIDO_USUARIO, 
               A.NOMBRE_ACTIVO, A.DIRECCION_IP, A.DIRECCION_MAC
        FROM INCIDENTE I
        JOIN USUARIO U ON I.USUARIO_ID = U.USUARIO_ID
        JOIN ACTIVO A ON I.ACTIVO_ID = A.ACTIVO_ID
        WHERE I.INCIDENTE_ID = v_incidente_id;
BEGIN
    v_incidente_id := id_incidente(p_descripcion_incidente);

    IF v_incidente_id IS NULL THEN
        DBMS_OUTPUT.PUT_LINE('El incidente con la descripción "' || p_descripcion_incidente || '" no existe.');
        RETURN;
    END IF;

    OPEN incidente_cursor;
    FETCH incidente_cursor INTO v_incidente_id, v_usuario_id, v_nombre_usuario, v_apellido_usuario, v_nombre_activo, v_direccion_ip, v_direccion_mac;
    IF incidente_cursor%FOUND THEN
        DBMS_OUTPUT.PUT_LINE('Código de incidente: ' || v_incidente_id);
        DBMS_OUTPUT.PUT_LINE('Nombre del usuario: ' || v_nombre_usuario || ' ' || v_apellido_usuario);
        DBMS_OUTPUT.PUT_LINE('Nombre del activo afectado: ' || v_nombre_activo);
        DBMS_OUTPUT.PUT_LINE('Dirección IP del activo: ' || v_direccion_ip);
        DBMS_OUTPUT.PUT_LINE('Dirección MAC del activo: ' || v_direccion_mac);
    END IF;
    CLOSE incidente_cursor;
END;
/




BEGIN
    mostrar_detalles_incidente_usuario_activo('Malware detectado');
END;
/








------------------------------------------------------------------
-- Procedimiento para mostrar los detalles de un 
-- incidente junto con su respuesta
------------------------------------------------------------------


CREATE OR REPLACE PROCEDURE mostrar_detalles_respuesta_incidente(
    p_descripcion_incidente IN VARCHAR2
) IS
    v_respuesta_id RESPUESTA_INCIDENTE.RESPUESTA_ID%TYPE;
    v_equipo_id RESPUESTA_INCIDENTE.EQUIPO_ID%TYPE;
    v_incidente_id RESPUESTA_INCIDENTE.INCIDENTE_ID%TYPE;
    v_vulnerabilidad_id RESPUESTA_INCIDENTE.VULNERABILIDAD_ID%TYPE;
    v_medidas_contencion RESPUESTA_INCIDENTE.MEDIDAS_CONTENCION%TYPE;
    v_nivel_erradicacion RESPUESTA_INCIDENTE.NIVEL_ERRADICACION%TYPE;
    v_nombre_equipo EQUIPO_IR.NOMBRE_EQUIPO%TYPE;
    v_nombre_vulnerabilidad VULNERABILIDAD.NOMBRE_VULNERABILIDAD%TYPE;
    v_nombre_activo ACTIVO.NOMBRE_ACTIVO%TYPE;

    CURSOR respuesta_cursor IS
        SELECT RI.RESPUESTA_ID, RI.EQUIPO_ID, RI.INCIDENTE_ID, RI.VULNERABILIDAD_ID,
               RI.MEDIDAS_CONTENCION, RI.NIVEL_ERRADICACION, E.NOMBRE_EQUIPO,
               V.NOMBRE_VULNERABILIDAD, A.NOMBRE_ACTIVO
        FROM RESPUESTA_INCIDENTE RI
        JOIN EQUIPO_IR E ON RI.EQUIPO_ID = E.EQUIPO_ID
        JOIN VULNERABILIDAD V ON RI.VULNERABILIDAD_ID = V.VULNERABILIDAD_ID
        JOIN INCIDENTE I ON RI.INCIDENTE_ID = I.INCIDENTE_ID
        JOIN ACTIVO A ON I.ACTIVO_ID = A.ACTIVO_ID
        WHERE I.INCIDENTE_ID = v_incidente_id;
BEGIN
    v_incidente_id := id_incidente(p_descripcion_incidente);

    IF v_incidente_id IS NULL THEN
        DBMS_OUTPUT.PUT_LINE('El incidente con la descripción "' || p_descripcion_incidente || '" no existe.');
        RETURN;
    END IF;

    OPEN respuesta_cursor;
    LOOP
        FETCH respuesta_cursor INTO v_respuesta_id, v_equipo_id, v_incidente_id,
                                   v_vulnerabilidad_id, v_medidas_contencion,
                                   v_nivel_erradicacion, v_nombre_equipo,
                                   v_nombre_vulnerabilidad, v_nombre_activo;
        EXIT WHEN respuesta_cursor%NOTFOUND;

        DBMS_OUTPUT.PUT_LINE('ID de respuesta: ' || v_respuesta_id);
        DBMS_OUTPUT.PUT_LINE('ID de incidente: ' || v_incidente_id);
        DBMS_OUTPUT.PUT_LINE('Nombre del incidente: ' || p_descripcion_incidente);
        DBMS_OUTPUT.PUT_LINE('Medidas de contención: ' || v_medidas_contencion);
        DBMS_OUTPUT.PUT_LINE('Nivel de erradicación: ' || v_nivel_erradicacion);
        DBMS_OUTPUT.PUT_LINE('Nombre del equipo: ' || v_nombre_equipo);
        
        -- Obtener los integrantes del equipo
        FOR integrante_rec IN (SELECT NOMBRE_PERSONAL_IR, ROL_PERSONAL_IR
                               FROM PERSONAL_IR
                               WHERE EQUIPO_ID = v_equipo_id) LOOP
            DBMS_OUTPUT.PUT_LINE('Integrante: ' || integrante_rec.NOMBRE_PERSONAL_IR || ', Rol: ' || integrante_rec.ROL_PERSONAL_IR);
        END LOOP;

        DBMS_OUTPUT.PUT_LINE('Nombre de vulnerabilidad: ' || v_nombre_vulnerabilidad);
        DBMS_OUTPUT.PUT_LINE('Nombre del activo: ' || v_nombre_activo);
    END LOOP;
    CLOSE respuesta_cursor;
END;
/


BEGIN
    mostrar_detalles_respuesta_incidente('Malware detectado');
END;
/
