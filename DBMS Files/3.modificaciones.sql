-- Modificaciones en USUARIO
UPDATE USUARIO SET EMAIL_USUARIO = 'acurasio@live.com' WHERE USUARIO_ID = 4;

-- Modificaciones en ACTIVO
UPDATE ACTIVO SET DIRECCION_IP = '192.168.1.10' WHERE ACTIVO_ID = 'A001';
UPDATE ACTIVO SET DIRECCION_MAC = '00:1A:2B:3C:4D:6H' WHERE ACTIVO_ID = 'A004';

-- Modificaciones en INCIDENTE
UPDATE INCIDENTE SET DESCRIPCION = 'Fuga de datos sensible' WHERE INCIDENTE_ID = 'I003';
UPDATE INCIDENTE SET ESTADO = 'Escalado' WHERE INCIDENTE_ID = 'I005';
