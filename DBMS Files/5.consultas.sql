-- Consulta 1: Incidentes reportados por cada usuario
SELECT USUARIO_ID, COUNT(*) AS TOTAL_INCIDENTES FROM INCIDENTE 
GROUP BY USUARIO_ID;

-- Consulta 2: Activos comprometidos por tipo de activo
SELECT TIPO_ACTIVO, COUNT(*) AS TOTAL_COMPROMETIDOS FROM ACTIVO
JOIN VULNERABILIDAD_ACTIVO ON ACTIVO.ACTIVO_ID = VULNERABILIDAD_ACTIVO.ACTIVO_ID
GROUP BY TIPO_ACTIVO;

-- Consulta 3: Nivel de erradicación por equipo de respuesta
SELECT EQUIPO_ID, NIVEL_ERRADICACION, COUNT(*) AS TOTAL_RESPUESTAS
FROM RESPUESTA_INCIDENTE
GROUP BY EQUIPO_ID, NIVEL_ERRADICACION;

-- Consulta 4: Vulnerabilidades más comunes en los activos
SELECT VULNERABILIDAD_ID, COUNT(*) AS TOTAL_VULNERABILIDADES
FROM VULNERABILIDAD_ACTIVO
GROUP BY VULNERABILIDAD_ID;

-- Consulta 5: Detalles de incidentes cerrados
SELECT I.INCIDENTE_ID, I.DESCRIPCION, I.FECHA, A.NOMBRE_ACTIVO, U.NOMBRE_USUARIO, U.APELLIDO_USUARIO
FROM INCIDENTE I
JOIN ACTIVO A ON I.ACTIVO_ID = A.ACTIVO_ID
JOIN USUARIO U ON I.USUARIO_ID = U.USUARIO_ID
WHERE I.ESTADO = 'Cerrado';

-- Consulta 6: Respuestas a incdentes con medidas de contención específicas
SELECT R.RESPUESTA_ID, R.INCIDENTE_ID, R.MEDIDAS_CONTENCION, E.NOMBRE_EQUIPO
FROM RESPUESTA_INCIDENTE R
JOIN EQUIPO_IR E ON R.EQUIPO_ID = E.EQUIPO_ID
WHERE R.MEDIDAS_CONTENCION LIKE '%parche%';

-- Consulta 7: Historial de cambios en activos comprometidos
SELECT VA.ACTIVO_ID, A.NOMBRE_ACTIVO, A.TIPO_ACTIVO, VA.DATOS_COMPROMETIDOS, V.NOMBRE_VULNERABILIDAD
FROM VULNERABILIDAD_ACTIVO VA
JOIN ACTIVO A ON VA.ACTIVO_ID = A.ACTIVO_ID
JOIN VULNERABILIDAD V ON VA.VULNERABILIDAD_ID = V.VULNERABILIDAD_ID;

-- Consulta 8: Incidentes por nivel de gravedad y estado
SELECT GRAVEDAD, ESTADO, COUNT(*) AS TOTAL_INCIDENTES
FROM INCIDENTE
GROUP BY GRAVEDAD, ESTADO;

-- Consulta 9: Información de personal de equipos de respuesta
SELECT P.PERSONAL_IR_ID, P.NOMBRE_PERSONAL_IR, P.APELLIDO_PERSONAL_IR, P.ROL_PERSONAL_IR, E.NOMBRE_EQUIPO
FROM PERSONAL_IR P
JOIN EQUIPO_IR E ON P.EQUIPO_ID = E.EQUIPO_ID;

-- Consulta 10: Detalles de incidentes relacionados con vulnerabilidades específicas
SELECT I.INCIDENTE_ID, I.DESCRIPCION, V.NOMBRE_VULNERABILIDAD, A.NOMBRE_ACTIVO, U.NOMBRE_USUARIO
FROM INCIDENTE I
JOIN RESPUESTA_INCIDENTE RI ON I.INCIDENTE_ID = RI.INCIDENTE_ID
JOIN VULNERABILIDAD V ON RI.VULNERABILIDAD_ID = V.VULNERABILIDAD_ID
JOIN ACTIVO A ON I.ACTIVO_ID = A.ACTIVO_ID
JOIN USUARIO U ON I.USUARIO_ID = U.USUARIO_ID;
