<h1>NetSpy - Packet Sniffer - README</h1>

<h2>Descripción del Proyecto</h2>

Este proyecto es un Packet Sniffer desarrollado utilizando la libreria Nppcap para la captura de paquetes, Programación Orientada a Objetos (POO) y con una implementación separada de la interfaz gráfica, desarrollada en Qt. Su principal función es capturar, analizar y mostrar información de los paquetes de red en tiempo real.

<h2>Requisitos Previos</h2>

Qt Creator y MinGW:

- Descarga e instala Qt Creator desde Qt Official Website.

- Durante la instalación, selecciona el kit de compilación MinGW.

Npcap:

- Descarga e instala Npcap desde Npcap Website.

Entorno de Desarrollo:

- Asegúrate de configurar correctamente las variables de entorno necesarias para MinGW y Qt Creator.

<h2>Configuración del Proyecto en Qt Creator</h2>

- Abre Qt Creator.

- Haz clic en File > Open File or Project....

- Selecciona el archivo .pro correspondiente al proyecto del Packet Sniffer.

- En la configuración del kit de compilación, selecciona MinGW como compilador.

<h2>Compilación del Proyecto</h2>

- Asegurate primero de descomprimir la carpeta build dentro del proyecto 

- Haz clic en el botón Build en la barra superior o presiona Ctrl + B.

- Asegúrate de que no haya errores durante la compilación.

- El ejecutable generado estará disponible en la carpeta build-<project_name>-<kit>.

<h2>Ejecución del Programa</h2>

- Antes de ejecutar el programa, verifica que tienes los permisos necesarios para capturar paquetes en tu red.

- Ejecuta el archivo generado desde Qt Creator o directamente desde la carpeta de salida.

- Selecciona un dispositivo de red desde la interfaz del programa para iniciar la captura de paquetes.

<h2>Estructura del Proyecto</h2>

<h3>Libreria Npcap</h3>

Se utilizo la libreria Npcap para poder utilizar sus funciones para la captura de paquetes, obtener su informacion y permitir su filtrado.

<h3>Clases y POO:</h3>

La captura de paquetes y el manejo de datos están organizados en clases, siguiendo los principios de la Programación Orientada a Objetos.

Ejemplo: Clase PacketCaptureThread para gestionar hilos de captura de paquetes.

<h3>Interfaz Gráfica:</h3>

Desarrollada separadamente utilizando las herramientas de diseño de Qt.

Usa QWidgets para la visualización de datos capturados en tiempo real.

<h2>Notas Importantes</h2>

<h3>Compatibilidad:</h3>

Este programa requiere Windows debido a la dependencia de Npcap.

<h3>Permisos:</h3>

Ejecuta el programa como administrador para garantizar el acceso a las interfaces de red.




© 2024 NetSpy Project. Todos los derechos reservados.
