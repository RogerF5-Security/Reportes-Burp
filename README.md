# 📊 Reportes - Extensión para Burp Suite

![Version](https://img.shields.io/badge/version-7.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Burp](https://img.shields.io/badge/Burp%20Suite-Community%20%7C%20Professional-orange.svg)
![Python](https://img.shields.io/badge/python-2.7%20(Jython)-yellow.svg)

**Reportes** es una extensión de reportería para Burp Suite que transforma la documentación de vulnerabilidades en un proceso automatizado, eficiente y profesional.

<p align="center">
  <img src="https://img.shields.io/badge/OWASP-Top%2010%202021-red.svg" alt="OWASP Top 10">
  <img src="https://img.shields.io/badge/vulnerabilities-40%2B-brightgreen.svg" alt="40+ Vulnerabilities">
  <img src="https://img.shields.io/badge/export-JSON%20%7C%20HTML%20%7C%20Faraday%20%7C%20DefectDojo-blueviolet.svg" alt="Export Formats">
</p>

---

## 🌟 Características Principales

### 🔍 Detección Automática
- ✅ Headers de seguridad faltantes (HSTS, CSP, X-Frame-Options, etc.)
- ✅ Cookies inseguras (sin Secure, HttpOnly, SameSite)
- ✅ Email disclosure
- ✅ Private IP disclosure (RFC 1918)
- ✅ Software version disclosure
- ✅ CORS misconfiguration

### 📚 Base de Datos Expandida
- **40+ vulnerabilidades predefinidas** con descripciones técnicas y soluciones
- Categorización completa **OWASP Top 10 2021**
- Mapping **CWE** (Common Weakness Enumeration)
- Templates **CVSS v3.1** por severidad
- Sistema de **tags** personalizables

### 📤 Exportación Multi-formato
| Formato | Descripción | Uso |
|---------|-------------|-----|
| **HTML** | Reporte profesional responsive | Cliente final |
| **JSON** | Formato completo con evidencias | Backup/Compartir |
| **Faraday** | Compatible con Faraday Platform | Gestión de vulnerabilidades |
| **DefectDojo** | Generic Findings Import | Tracking y workflow |

### 🎯 Gestión Avanzada
- 🔄 **Auto-save automático** - Nunca pierdas tu trabajo
- 🔍 **Búsqueda en tiempo real** - Encuentra hallazgos instantáneamente
- 🏷️ **Filtros múltiples** - Por severidad, categoría OWASP, scope
- ✏️ **Editor completo** - Modifica cualquier aspecto de los hallazgos
- 📊 **Estadísticas en vivo** - Dashboard con métricas actualizadas

---

## 📥 Instalación Paso a Paso

### Paso 1: Descargar Jython

Burp Suite necesita **Jython** (implementación de Python en Java) para ejecutar extensiones Python.

#### 1.1. Ve a la página oficial de Jython

Abre tu navegador y ve a:
```
https://www.jython.org/download
```

#### 1.2. Descarga Jython Standalone JAR

- Busca la sección **"Jython Standalone"**
- Descarga la versión **2.7.3** o superior
- Archivo: `jython-standalone-2.7.3.jar`

**Nota:** El archivo JAR es auto-contenido y no requiere instalación de Python.

#### 1.3. Guarda el archivo en ubicación conocida

Ejemplos:
- **Windows:** `C:\Tools\jython-standalone-2.7.3.jar`
- **Linux:** `/opt/jython-standalone-2.7.3.jar`
- **macOS:** `/Applications/jython-standalone-2.7.3.jar`

---

### Paso 2: Configurar Jython en Burp Suite

#### 2.1. Abre Burp Suite

Inicia Burp Suite (Community o Professional Edition)

#### 2.2. Ve a la configuración de extensiones

1. Click en la pestaña **"Extensions"**
2. Click en la sub-pestaña **"Options"**

```
┌─────────────────────────────────────────┐
│ Burp Suite                              │
├─────────────────────────────────────────┤
│ Dashboard  Target  Proxy  [Extensions] .. │
│                                         │
│ ┌───────────────────────────────────┐  │
│ │ [Extensions] [BApp Store] Options │  │
│ └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

#### 2.3. Configura la ubicación de Jython

1. Busca la sección **"Python Environment"**
2. Encontrarás: "Location of Jython standalone JAR file"
3. Click en el botón **"Select file..."**

```
┌──────────────────────────────────────────────┐
│ Python Environment                           │
├──────────────────────────────────────────────┤
│                                              │
│ Location of Jython standalone JAR file:     │
│ ┌──────────────────────────┐ ┌───────────┐ │
│ │ /path/to/jython-...      │ │Select file│ │
│ └──────────────────────────┘ └───────────┘ │
└──────────────────────────────────────────────┘
```

#### 2.4. Selecciona el archivo JAR

1. Navega a donde guardaste `jython-standalone-2.7.3.jar`
2. Selecciona el archivo
3. Click **"Open"**

#### 2.5. Verifica la configuración

Deberías ver la ruta completa del archivo JAR en el campo:

```
✅ Location: C:\Tools\jython-standalone-2.7.3.jar
```

**¡Jython configurado correctamente!** ✓

---

### Paso 3: Descargar la Extensión Reportes

#### Opción A: Clonar el repositorio (Recomendado)

```bash
git clone https://github.com/tuusuario/burp-reportes.git
cd burp-reportes
```

#### Opción B: Descargar archivo directamente

1. Ve al repositorio en GitHub
2. Click en el archivo **`ReportesProComplete.py`**
3. Click en el botón **"Raw"**
4. Click derecho → **"Guardar como..."**
5. Guarda como `ReportesProComplete.py`

#### Opción C: Descargar release

```bash
wget https://github.com/tuusuario/burp-reportes/releases/latest/download/ReportesProComplete.py
```

---

### Paso 4: Cargar la Extensión en Burp Suite

#### 4.1. Abre el diálogo de extensiones

1. En Burp Suite, ve a **"Extensions"** → **"Extensions"**
2. Click en el botón **"Add"**

```
┌──────────────────────────────────────────┐
│ Extensions > Extensions                    │
├──────────────────────────────────────────┤
│ ┌─────┐                                  │
│ │ Add │  Remove                          │
│ └─────┘                                  │
│                                          │
│ Loaded Extensions:                       │
│ ┌────────────────────────────────────┐  │
│ │ No extensions loaded               │  │
│ └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

#### 4.2. Configura el tipo de extensión

En el diálogo "Load Burp Extension":

1. **Extension type:** Selecciona **"Python"** del dropdown

```
┌─────────────────────────────────────────┐
│ Load Burp Extension                     │
├─────────────────────────────────────────┤
│                                         │
│ Extension Details:                      │
│                                         │
│ Extension type: ┌──────────────────┐   │
│                 │ ▼ Python         │   │
│                 │   Java           │   │
│                 │   Ruby           │   │
│                 └──────────────────┘   │
└─────────────────────────────────────────┘
```

**⚠️ IMPORTANTE:** Asegúrate de seleccionar **"Python"** y NO "Java"

#### 4.3. Selecciona el archivo de la extensión

1. **Extension file:** Click en **"Select file..."**
2. Navega a donde descargaste `ReportesProComplete.py`
3. Selecciona el archivo
4. Click **"Open"**

```
┌─────────────────────────────────────────┐
│ Extension file (.py):                   │
│ ┌───────────────────────┐ ┌──────────┐ │
│ │ ReportesProComplete.py│ │Select... │ │
│ └───────────────────────┘ └──────────┘ │
└─────────────────────────────────────────┘
```

#### 4.4. Carga la extensión

1. Click en el botón **"Next"**
2. Burp cargará la extensión y mostrará la salida en la consola

```
┌──────────────────────────────────────────────────┐
│ Output:                                          │
├──────────────────────────────────────────────────┤
│ ================================================ │
│ >>> Reportesfessional v7.0                   │
│ >>> Enhanced Edition                             │
│ >>> Caracteristicas:                             │
│     - Auto-save/load automatico                  │
│     - Exportacion Faraday/DefectDojo/JSON/HTML   │
│     - 40+ vulnerabilidades predefinidas          │
│     - Categorizacion OWASP Top 10 2021           │
│     - Busqueda y filtros avanzados               │
│ ================================================ │
└──────────────────────────────────────────────────┘
```

#### 4.5. Cierra el diálogo

Click en **"Close"**

---

### Paso 5: Verificar la Instalación

#### 5.1. Verifica la nueva pestaña

Deberías ver una nueva pestaña llamada **"Reportes"** en la barra superior de Burp:

```
┌──────────────────────────────────────────────────────┐
│ Dashboard  Target  Proxy  Intruder  [Reportes]  │
└──────────────────────────────────────────────────────┘
```

#### 5.2. Verifica la extensión cargada

En **Extensions** → **Extensions**, deberías ver:

```
┌────────────────────────────────────────────────────┐
│ Loaded Extensions:                                 │
├────────────────────────────────────────────────────┤
│ ✓ Reportesfessional v7.0          [Loaded]    │
│   Type: Python                                     │
│   Output: [View]  Errors: [None]                  │
└────────────────────────────────────────────────────┘
```

**Estado esperado:**
- ✅ Indicador verde (✓)
- ✅ Estado: "Loaded"
- ✅ Errors: "None" o vacío

#### 5.3. Prueba la extensión

1. Click en la pestaña **"Reportes"**
2. Deberías ver la interfaz con:
   - Toolbar con botones (Nuevo, Guardar, Cargar, Exportar, etc.)
   - Tabla vacía con columnas (ID, Host, Path, Vulnerabilidad, etc.)
   - Panel de estadísticas a la derecha
   - Panel de evidencias en la parte inferior

```
┌──────────────────────────────────────────────────────────┐
│ Reportes                                                 │
├──────────────────────────────────────────────────────────┤
│ [Nuevo] [Guardar] [Cargar] | [HTML] [JSON] [Faraday]... │
│                                                          │
│ Buscar: [________]  Severidad: [Todas ▼]  ...           │
│                                                          │
│ ┌──────────────────────────────────┐ ┌────────────────┐ │
│ │ ID│Host│Path│Vulnerabilidad│... │ │ Estadisticas   │ │
│ │   │    │    │              │    │ │ Total: 0       │ │
│ │   │    │    │  (vacía)     │    │ │ Critical: 0    │ │
│ │   │    │    │              │    │ │ High: 0        │ │
│ └──────────────────────────────────┘ └────────────────┘ │
│                                                          │
│ ┌────────────────────────────────────────────────────┐  │
│ │ [Detalles] [Request] [Response]                    │  │
│ └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

**¡Instalación completada exitosamente!** 🎉

---

## 🚀 Guía de Uso Rápido

### Primera Configuración Recomendada

1. **Configurar Scope (Opcional pero recomendado)**
   - Ve a **Target** → **Scope**
   - Agrega la URL de tu aplicación objetivo
   - En **Reportes**, marca **"Solo Scope"**

2. **Verificar Auto-save**
   - Checkbox **"Auto-save"** debe estar marcado ✓
   - Esto guarda tu trabajo automáticamente

### Captura Automática de Vulnerabilidades

La extensión detecta automáticamente mientras navegas:

#### Paso a Paso:

1. **Configura tu navegador** con el proxy de Burp:
   - Proxy: `127.0.0.1`
   - Puerto: `8080` (por defecto)

2. **Activa Intercept** en Burp:
   - **Proxy** → **Intercept** → **Intercept is on**

3. **Navega la aplicación web** objetivo en tu navegador

4. **Ve a Reportes** para ver hallazgos automáticos:
   ```
   ✓ Headers de Seguridad Faltantes (Medium)
   ✓ Cookie Insegura (Medium)
   ✓ Email Disclosure (Info)
   ✓ Software Version Disclosure (Info)
   ```

### Agregar Vulnerabilidades Manualmente

#### Método 1: Desde cualquier herramienta de Burp

1. En **Proxy**, **Repeater**, **Intruder**, etc., encuentra una vulnerabilidad

2. **Click derecho** en el request

3. Selecciona **"Agregar Hallazgo Manual"**

4. Completa el formulario:
   ```
   Plantilla:     [SQL Injection ▼]  ← Auto-completa campos
   Título:        SQL Injection en login
   Severidad:     [Critical ▼]
   Tags:          injection, authentication, critical
   Descripción:   Union-based SQLi en parámetro 'username'
   Solución:      Implementar prepared statements
   ```

5. Click **OK**

#### Método 2: Envío Rápido

1. **Click derecho** → **"Enviar a Reportes"**
2. Escribe título rápido: `XSS en search`
3. Click **OK**

**Resultado:** El hallazgo aparece inmediatamente en la tabla de Reportes.

### Buscar y Filtrar

#### Búsqueda en Tiempo Real

Escribe en el campo **"Buscar:"**:
- `login` → Muestra hallazgos relacionados con login
- `192.168` → Muestra IP disclosures
- `xss` → Muestra hallazgos XSS

#### Filtros Combinados

Ejemplo: Encontrar todas las inyecciones críticas en endpoints de API

```
Buscar:     api
Severidad:  Critical
Categoria:  A03:2021 - Injection
```

### Editar Hallazgos

1. **Click** en un hallazgo de la tabla (selecciona la fila)

2. Click botón **"Editar"**

3. Modifica lo que necesites:
   - Cambiar severidad de Medium a High
   - Agregar tags: `confirmed, production`
   - Agregar notas: `Verified in production environment. POC available.`

4. Click **OK**

5. Cambios guardados automáticamente ✓

### Exportar Reportes

#### HTML - Reporte Profesional

```
1. Click "HTML"
2. Completar:
   Proyecto:  Auditoría Web - E-commerce XYZ
   Cliente:   XYZ Corporation
   Auditor:   Tu Nombre / Equipo
   Resumen:   Se identificaron 15 vulnerabilidades...
3. Click OK
4. Guardar como: reporte_xyz_2026.html
5. ✅ Reporte HTML generado
```

**Contenido del reporte:**
- Dashboard con métricas por severidad
- Resumen ejecutivo
- Distribución OWASP Top 10
- Hallazgos detallados con Request/Response
- Diseño profesional y responsive
- Listo para PDF (Ctrl+P en navegador)

#### Faraday - Gestión de Vulnerabilidades

```bash
# 1. En Reportes: Click "Faraday" → Guardar
# 2. En terminal:

faraday-cli auth -f http://faraday:5985 -u analyst -p pass
faraday-cli workspace create WebApp_XYZ
faraday-cli workspace select WebApp_XYZ
faraday-cli tool report pentest_xyz.json

# ✅ Vulnerabilidades importadas en Faraday
```

#### DefectDojo - Tracking

```
1. En Reportes: Click "DefectDojo" → Guardar
2. En DefectDojo Web UI:
   - Engagements → Import Scan Results
   - Scan Type: "Generic Findings Import"
   - File: Subir archivo JSON
   - Submit
3. ✅ Hallazgos importados
```

#### JSON - Backup/Compartir

```
Click "JSON" → Guardar como: proyecto_completo.json

Contenido:
- Todos los hallazgos con metadata
- Request/Response en base64
- Compatible para recargar con "Cargar"
```

### Guardar y Cargar Proyectos

#### Auto-save (Predeterminado)

```
✓ Checkbox "Auto-save" marcado
→ Se guarda automáticamente cada cambio
→ Ubicación: /tmp/burp_reportes_autosave.json
→ Se carga automáticamente al abrir Burp
```

**No necesitas hacer nada, está funcionando en segundo plano.**

#### Guardar Manualmente

```
1. Click "Guardar"
2. Primera vez: Selecciona ubicación
   → Ejemplo: ~/Proyectos/cliente_xyz.json
3. Siguientes veces: Sobrescribe automáticamente
```

#### Cargar Proyecto

```
1. Click "Cargar"
2. Selecciona archivo: cliente_xyz.json
3. ✅ Proyecto cargado con todos los hallazgos
```

**Nota:** Request/Response originales no se preservan al cargar (limitación de Burp API).

---

## 📋 Lista de Vulnerabilidades Incluidas

### Injection (A03:2021)

- ✅ SQL Injection (Critical)
- ✅ XSS Reflected (High)
- ✅ XSS Stored (Critical)
- ✅ Command Injection (Critical)
- ✅ LDAP Injection (High)

### Broken Access Control (A01:2021)

- ✅ IDOR - Insecure Direct Object Reference (High)
- ✅ Path Traversal (High)
- ✅ Privilege Escalation (Critical)
- ✅ Missing Function Level Access Control (High)

### Authentication Failures (A07:2021)

- ✅ Broken Authentication (Critical)
- ✅ Session Fixation (High)
- ✅ Weak Password Policy (Medium)
- ✅ Credential Exposure (Critical)

### Cryptographic Failures (A02:2021)

- ✅ Weak Encryption Algorithm (High)
- ✅ Sensitive Data Exposure (High)
- ✅ Insecure SSL/TLS Configuration (High)

### Security Misconfiguration (A05:2021)

- ✅ Missing Security Headers (Medium)
- ✅ Insecure Cookie Configuration (Medium)
- ✅ Directory Listing Enabled (Low)
- ✅ Verbose Error Messages (Low)
- ✅ CORS Misconfiguration (Medium)
- ✅ Default Credentials (Critical)

### Other Categories

- ✅ SSRF - Server-Side Request Forgery (High)
- ✅ CSRF - Cross-Site Request Forgery (Medium)
- ✅ Business Logic Flaw (High)
- ✅ Rate Limiting Missing (Medium)
- ✅ API - Broken Object Level Authorization (High)
- ✅ API - Excessive Data Exposure (Medium)
- ✅ API - Mass Assignment (High)
- ✅ API - Missing Rate Limiting (Medium)
- ✅ Email Disclosure (Info)
- ✅ Private IP Disclosure (Low)
- ✅ Software Version Disclosure (Info)
- ✅ Backup File Disclosure (Medium)
- ✅ Source Code Disclosure (High)
- ✅ Outdated Component (High)

**Total: 40+ vulnerabilidades predefinidas**

---

## 🔧 Troubleshooting

### ❌ "Extension failed to load"

**Causa:** Jython no configurado o ruta incorrecta

**Solución:**
```
1. Extensions → Options → Python Environment
2. Verificar ruta del JAR es correcta
3. Re-seleccionar archivo jython-standalone-2.7.3.jar
4. Reiniciar Burp Suite
5. Cargar extensión nuevamente
```

### ❌ "No module named burp"

**Causa:** Tipo de extensión incorrecto

**Solución:**
```
Al cargar extensión, verificar:
✓ Extension type: Python (NO Java)
```

### ❌ Auto-save no funciona

**Causa:** Permisos de escritura en /tmp

**Solución (Linux/Mac):**
```bash
chmod 777 /tmp
```

**Solución (Windows):**
```
Editar línea 1180 del código:
temp_dir = "C:\\Users\\TuUsuario\\AppData\\Local\\Temp"
```

### ❌ No se detectan vulnerabilidades

**Causa:** "Solo Scope" activo sin scope configurado

**Solución:**
```
Opción 1: Desmarcar "Solo Scope"
Opción 2: Configurar scope en Target → Scope
```

### ❌ Request/Response no se muestran

**Causa:** Hallazgo cargado desde JSON

**Explicación:**
```
Esto es normal. Los hallazgos cargados desde JSON
no incluyen Request/Response originales (limitación API).

Para hallazgos nuevos: Siempre agregar desde click derecho
en un request específico para capturar evidencias.
```

---


### Ideas para contribuir:

- 📝 Agregar más vulnerabilidades
- 🎨 Mejorar diseño HTML
- 🔍 Nuevos patrones de detección
- 🌐 Traducciones
- 📊 Nuevos formatos de exportación

---

## 📄 Licencia

MIT License - Ver archivo [LICENSE](LICENSE) para más detalles.

---

## 👨‍💻 Autor

**Roger F5** - Versión Original

**Enhanced Edition** - Mejoras y funcionalidades avanzadas

---

## 🔗 Enlaces Útiles

- [Burp Suite](https://portswigger.net/burp)
- [Jython](https://www.jython.org/)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE List](https://cwe.mitre.org/)
- [Faraday](https://github.com/infobyte/faraday)
- [DefectDojo](https://github.com/DefectDojo/django-DefectDojo)

---

## ⭐ Si te ayuda, ¡deja una estrella!

<p align="center">
  <b>Hecho con ❤️ para la comunidad de seguridad</b>
</p>

<p align="center">
  <sub>¿Te ahorra tiempo? Considera ⭐ el proyecto</sub>
</p>
