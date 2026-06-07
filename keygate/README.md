# KeyGate

Tokens de acceso para tu propio PC -- como los Personal Access Tokens de GitHub, pero el servidor eres tu.

Author: Victor Martin Sotoca
License: Apache 2.0

---

## Que es

KeyGate te permite generar tokens con permisos (lectura, escritura, admin) para que otros equipos
--o tu mismo desde fuera-- se conecten a tu PC y hagan operaciones autorizadas: leer archivos,
escribir, listar directorios, ejecutar comandos.

    [Tu PC - Servidor]          [Otro PC - Cliente]
      server.py start    <---     client.py --host IP --token kg_xxx ping
      tokens.json

---

## Instalacion

    cd keygate
    python3 install.py

O instala solo las dependencias:

    pip install cryptography

---

## Uso rapido

### 1. En tu PC (el servidor)

Crear un token:

    python3 server/server.py token create

Ejemplo de salida:

    Nombre del token: laptop-victor
    Permisos (separados por coma): read,write
    Expiracion en dias (vacio = sin limite): 30

    Token creado exitosamente

      Nombre  : laptop-victor
      Permisos: read, write
      Expira  : 2025-08-10

      TOKEN (copialo ahora, no se volvera a mostrar):

         kg_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcde

Arrancar el servidor:

    python3 server/server.py start
    # Por defecto escucha en 0.0.0.0:7331
    # Puerto personalizado:
    python3 server/server.py start --port 9000

Ver todos los tokens:

    python3 server/server.py token list

Revocar un token:

    python3 server/server.py token revoke

---

### 2. Desde otro PC (el cliente)

    # Ping basico
    python3 client/client.py --host 192.168.1.10 --token kg_xxx ping

    # Info del sistema remoto (requiere 'read')
    python3 client/client.py --host 192.168.1.10 --token kg_xxx info

    # Leer un archivo remoto (requiere 'read')
    python3 client/client.py --host 192.168.1.10 --token kg_xxx read ~/proyecto/config.json

    # Listar directorio (requiere 'read')
    python3 client/client.py --host 192.168.1.10 --token kg_xxx ls ~/Documentos

    # Escribir un archivo (requiere 'write')
    python3 client/client.py --host 192.168.1.10 --token kg_xxx write ~/destino.txt "hola mundo"

    # Escribir desde stdin (requiere 'write')
    cat archivo_local.py | python3 client/client.py --host 192.168.1.10 --token kg_xxx write ~/remoto.py -

    # Eliminar un archivo (requiere 'write')
    python3 client/client.py --host 192.168.1.10 --token kg_xxx delete ~/archivo.txt

    # Ejecutar un comando (requiere 'admin')
    python3 client/client.py --host 192.168.1.10 --token kg_xxx exec "df -h"
    python3 client/client.py --host 192.168.1.10 --token kg_xxx exec "git pull"

---

## Perfiles (evita escribir host/token cada vez)

    # Guardar un perfil
    python3 client/client.py profile save

    # Activar un perfil
    python3 client/client.py profile use mi-pc

    # Listar perfiles
    python3 client/client.py profile list

    # Con el perfil activo, ya no necesitas --host ni --token
    python3 client/client.py ping
    python3 client/client.py ls ~/

---

## Permisos

  Permiso   Acciones permitidas
  -------   ---------------------------------------------------
  read      ping, info, read_file, list_dir
  write     todo lo de read + write_file, delete_file
  admin     todo lo anterior + exec (ejecutar comandos)

Puedes combinar permisos: read,write o dar solo read para acceso de solo lectura.

---

## Estructura del proyecto

    keygate/
    |-- server/
    |   +-- server.py       <- corre en tu PC
    |-- client/
    |   +-- client.py       <- se conecta al servidor
    |-- shared/
    |   +-- models.py       <- Token, TokenStore, Perm
    |-- LICENSE
    |-- install.py
    +-- README.md

---

## Datos y seguridad

- Los tokens se almacenan hasheados (SHA-256) en ~/.keygate/tokens.json
- El token en crudo nunca se guarda, solo se muestra una vez al crearlo
- Formato del token: kg_ + 40 caracteres aleatorios (256 bits de entropia)
- Los logs se guardan en ~/.keygate/server.log
- Para produccion, combina con un tunnel TLS (ej. cloudflared o certificado propio)

---

## Abrir el puerto en tu red local

Si quieres conectarte desde fuera de tu red WiFi:
1. En tu router, haz port forwarding del puerto 7331 hacia tu PC
2. Usa tu IP publica como --host
3. (Recomendado) Pon el servidor detras de un proxy con TLS

---

## Licencia

Apache 2.0 -- ver el archivo LICENSE
