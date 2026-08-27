# Vista previa del Ethical Hacking

**Anexo de `SECURITY_CODE_REVIEW.md` v1.3** · 2026-08-24
**Propósito:** anticipar qué encontrará la empresa que ejecute el Ethical Hacking, para poder cerrarlo antes.

Este documento **no sustituye al informe completo**. Filtra sus 46 hallazgos por un único criterio —*¿es observable desde fuera?*— y añade los que aparecieron al re-escanear el código con esa lente.

---

## 1. Modelo de atacante asumido

Derivado de la reunión con Arquitectura (transcripción del 2026-08-24) y del diagrama PRE/PROD:

| | |
|---|---|
| **Tipo de prueba** | Caja negra / grey box. **No hay revisión de código fuente** |
| **Punto de entrada** | A través del API Gateway (*"para consumir ese microservicio tienes que pasar por el apigateway"*) |
| **Credenciales** | Entregadas por el equipo: token de Cognito, o `client_id` + `client_secret` |
| **Insumo** | Listado de endpoints con su mecanismo de autenticación |
| **Pruebas anticipadas** | Sin cabecera · cabecera alterada · token expirado · token de otro usuario · token de otra app · inyección SQL · movimiento entre microservicios · ficheros maliciosos al DMS |

Es un alcance estándar de la industria. Los proveedores de *grey box* suelen pedir precisamente esto: colección Postman, endpoints y una llamada de alineación sobre el flujo de autenticación.

### 1.1 Qué implica el punto de entrada

**Con el gateway delante, las pruebas de autenticación las para el perímetro:**

| Prueba anticipada | Resultado real | Hallazgo enmascarado |
|---|---|---|
| Sin `Authorization` | 401 del gateway | SEC-001 |
| Token expirado | 401 del gateway | SEC-001 |
| Firma alterada | 401 del gateway | SEC-001 |

Esto es importante y hay que decirlo con claridad: **el EH no detectará que el backend no valida el token**. `santander.security.enabled: false` y `anyRequest().permitAll()` quedarán invisibles, porque nunca llegará al pod una petición sin token válido.

**En cuanto el token es válido, el gateway deja de filtrar.** Todo lo que sigue es autorización y lógica de negocio, que es donde el código falla y donde ningún WAF ayuda.

### 1.2 Advertencia sobre el resultado

Si el EH cubre solo el flujo a través del gateway y sale limpio en autenticación, el informe dirá **"autenticación correcta"**. No lo es: simplemente nunca se prueba. Sería un aprobado sobre una capa que no existe.

**Pregunta a resolver con Arquitectura antes del EH:** ¿el alcance incluye un escenario de red interna o de contenedor comprometido? En banca es habitual incluirlo. Si lo incluye, SEC-001 y SEC-021 pasan a primera línea; si no, quedan como deuda técnica no cubierta por la prueba.

---

## 2. Mapeo OWASP API Security Top 10 2023

Es el marco que utilizará casi con seguridad el proveedor.

| Categoría OWASP | ¿Lo encontrará? | Hallazgos |
|---|---|---|
| **API1 — Broken Object Level Authorization** | **Sí, con alta probabilidad** | SEC-002, SEC-047, SEC-049 |
| **API2 — Broken Authentication** | Parcialmente (el gateway lo tapa) | SEC-005 sí · SEC-001 no |
| **API3 — Broken Object Property Level Authorization** | **Sí** | SEC-048 |
| **API4 — Unrestricted Resource Consumption** | **Sí** | SEC-014, SEC-019, SEC-020, SEC-039 |
| **API5 — Broken Function Level Authorization** | Posible | SEC-021 |
| **API6 — Unrestricted Access to Sensitive Business Flows** | **Sí** | SEC-005, SEC-019, SEC-037 |
| **API7 — Server Side Request Forgery** | No | Analizado y descartado (§14) |
| **API8 — Security Misconfiguration** | Depende del gateway | SEC-022, SEC-025, SEC-028 |
| **API9 — Improper Inventory Management** | **Sí** | SEC-046, SEC-052 |
| **API10 — Unsafe Consumption of APIs** | **Sí** | SEC-018, SEC-040 |

Nueve de diez categorías tienen al menos un hallazgo asociado. La única limpia es SSRF, verificada y descartada.

---

## 3. Casos de prueba y resultado esperado

Ordenados por probabilidad de que el proveedor los ejecute. Cada uno corresponde a una prueba que Arquitectura ya anticipó o a un caso estándar del marco OWASP.

### CP-01 · Token válido, identificador de otro cliente → **BOLA**

> Anticipado por Arquitectura: *"el token va a tener otro usuario, va a tener otro AP"*

```http
GET /v1/customer_card_position/list?customer_id=<cliente ajeno>
Authorization: Bearer <token válido del atacante>
```

**Resultado esperado: 200 con la posición de tarjetas del otro cliente.** El gateway lo acepta porque el token es válido; el pod no comprueba titularidad.

Repetible en: `becreditrisk` (`documentNumber` en el cuerpo), `bedatacomanagment` (`party_id`), `bedocmanagement` (`document_id`), `beknowyocustomer` (`questionnaire_id`), `becustombeprogrm` (`key`).

**Hallazgo:** SEC-002 · **API1** · Es el hallazgo más probable y más grave del EH.

### CP-02 · Enumeración diferencial de documentos ← *nuevo*

Tres endpoints responden distinto ante el mismo identificador inexistente:

| Petición | Documento existe | No existe |
|---|---|---|
| `POST /download_document` | 200 + URL | **404** |
| `GET /documents/{id}` | 200 + metadatos | **200 + objeto vacío** |
| `DELETE /documents/{id}` | 204 | **204** |

La diferencia 404 / 200-vacío permite **enumerar qué identificadores existen** sin necesidad de acceder a ellos. Es el primer paso de cualquier ataque sobre objetos.

**Hallazgo:** SEC-047 · **API1**

### CP-03 · DNI del titular expuesto en los metadatos ← *nuevo*

```http
GET /v2/document_management/documents/{document_id}
```

`DocumentMapper.getMapper()` construye la respuesta con `response.setName(entity.getName())`, y `FileEntity.name` contiene el `ownerId` del titular. **El campo `name` de la respuesta devuelve el documento de identidad del titular.**

Encadenado con SEC-014 (`/documents/{id}/versions` devuelve los nombres de fichero de *todos* los documentos), se obtiene el repositorio documental completo y el DNI del titular de cada pieza.

**Hallazgo:** SEC-048 · **API3**

### CP-04 · Fichero malicioso al gestor documental

> Anticipado por Arquitectura: *"le envía un documento en PDF, otro en imagen, otro en PDF con algo encriptado por dentro"*

```http
POST /v2/document_management/upload_document
{ "document": { "folderReference": "<base64 de un HTML>",
                "mimeType": "application/pdf",
                "name": "informe.pdf",
                "owners": [ { "ownerId": "<DNI ajeno>" } ] } }
```

Tres defectos concurrentes:
- El `mimeType` lo declara el cliente y se almacena tal cual. Tika solo se invoca si `callerInformation.appId == "biometric"`.
- La clave S3 se compone con `ownerId` + `name` sin sanear → colocación en el espacio de otro titular y sobrescritura.
- Sin límite de tamaño del base64.

**Hallazgos:** SEC-015, SEC-020 · **API3, API4**

### CP-05 · Borrado sin verificación ← *nuevo*

```http
DELETE /v2/document_management/documents/{document_id}
```

`deleteDocument` no comprueba titularidad y devuelve **204 tanto si borra como si el documento no existía**. Un tercero con token válido elimina el objeto de S3 y su registro. La respuesta uniforme dificulta además detectar el abuso.

**Hallazgo:** SEC-049 · **API1**

### CP-06 · Abuso del flujo de OTP

```http
POST /v1/emailboxes/{emailbox_id}/send_email      → genera OTP al destinatario indicado
POST /v1/emailboxes/{id}/emails/{OTP}/classify_email → valida sin comprobar de quién es
```

`validCode` busca el OTP como clave primaria en DynamoDB, sin vincularlo a usuario ni operación, y la condición de éxito es `status != null`. Sin límite de intentos ni de generación.

Tres vectores: OTP propio para autorizar operación ajena · fuerza bruta · abuso de envío de correo a destinatarios arbitrarios.

**Hallazgo:** SEC-005 · **API2, API6**

### CP-07 · Movimiento entre microservicios

> Anticipado por Arquitectura: *"va a querer que tu microservicio se conecte con otro microservicio"*

`bedigitsignature` invoca `POST /v2/document_management/download_document_intern` con cabeceras estáticas (`x-santander-client-id: 123`, `channel: App-Nube`, `society: scp`) que `bedocmanagement` **no valida**. Los valores están en el repositorio.

Si el proveedor consigue que un endpoint legítimo dispare esa llamada con un `idDocumento` ajeno, atraviesa la frontera sin pasar por el gateway.

**Hallazgo:** SEC-021 · **API5**

### CP-08 · Agotamiento de recursos

| Vector | Efecto |
|---|---|
| `GET /documents/{id}/versions` | Scan completo de DynamoDB por petición |
| `POST /search_documents` | Scan completo con filtro |
| `POST /signature/signer` con N documentos | 1 petición → 2N llamadas externas |
| base64 de cientos de MB | Decodificación íntegra en memoria |

**Hallazgos:** SEC-014, SEC-039, SEC-019, SEC-020 · **API4**

### CP-09 · Provocar 500 con entradas límite

Puntos confirmados donde una entrada válida según el contrato produce excepción no controlada:

| Petición | Excepción |
|---|---|
| `PATCH /categories/{benefit_program_id}` con valor ≠ `UP`/`DOWN` | `IllegalArgumentException` |
| `POST /signature/signer` con `idDocumento` inexistente | `NoSuchElementException` (`.findFirst().get()`) |
| `POST /signature/signer` sin `documentos` | `NullPointerException` |
| `POST /send_email` con `templateId` no numérico | `NumberFormatException` |
| `POST /search_documents` con `keyId` inválido | `IllegalArgumentException` |

Ningún `ControllerAdvice` declara manejador para `Exception`.

**Hallazgo:** SEC-028 · **API8**

### CP-10 · El path controla el verbo HTTP saliente ← *nuevo*

En `becustombeprogrm`, el path variable `{benefit_program_id}` se usa como acción: `UP` → `PATCH`, `DOWN` → `DELETE` contra el proveedor Qurable. Un valor distinto produce excepción no controlada.

Que un parámetro de ruta determine el método HTTP hacia un tercero es un patrón que cualquier pentester marcará, aunque hoy el conjunto esté acotado a dos valores.

**Hallazgo:** SEC-050 · **API8**

### CP-11 · Fail-open en el Libro de Reclamaciones

```http
POST /v1/claims_book/claims
```

Si el proveedor falla, `ClaimsAdapter.createClaims` devuelve **200 OK con `complaintBookId: "56782902"` fijo**. `getClaims` devuelve datos de una persona ficticia (`documentNumber: "12345678"`).

Detectable comparando respuestas: el mismo identificador constante en peticiones distintas lo delata de inmediato.

**Hallazgo:** SEC-010 · **API8** · Impacto regulatorio (INDECOPI)

### CP-12 · Superficie declarada no implementada ← *nuevo*

`beknowyocustomer` declara 20 operaciones e implementa 2; el resto responde **501 Not Implemented** desde el método por defecto del generador. `bedatacomanagment` implementa 3 de 8.

Un `501` confirma al proveedor que el endpoint existe en el contrato pero no está implementado — información de inventario que se reporta como **API9**.

**Hallazgo:** SEC-052 · **API9**

### CP-13 · Respuestas de proveedores externos sin sanear

`becustombeprogrm` devuelve el cuerpo de error de SKY íntegro cuando no puede parsearlo; `bedigitsignature` incrusta `Status=…, body=…` del proveedor en la respuesta al consumidor.

Enviando peticiones malformadas se recolectan mensajes internos del tercero.

**Hallazgos:** SEC-018 · **API10**

### CP-14 · Validación AML que siempre responde igual

`GET/POST /v1/watchlist_screening/validate_status` devuelve `validationResult.result = "Match Found"` **en todos los casos**, haya coincidencia o no. La distinción real solo aparece en `riskSourceCode`.

Dos peticiones con perfiles opuestos devuelven el mismo veredicto: fácil de detectar y difícil de justificar en un control AML.

**Hallazgo:** SEC-040 · **API10**

### CP-15 · Valor mágico en la entrada

`documentId = "CONTRATO_CLIENTE"` desvía el flujo a un PDF empaquetado en el JAR, evitando la consulta al gestor documental. Es el tipo de cadena que aparece al fuzzear con diccionarios.

**Hallazgo:** SEC-032 · **API8**

---

## 4. Hallazgos nuevos de este re-escaneo

Aparecieron al revisar el código con criterio de observabilidad externa. Deben incorporarse al informe principal.

| ID | Severidad | Hallazgo | Componente | OWASP |
|---|---|---|---|---|
| SEC-047 | High | Enumeración diferencial: 3 endpoints, 3 respuestas ante recurso inexistente | `DocumentManagementAdapter:61-71,178-185,200-215` | API1 |
| SEC-048 | High | El DNI del titular se devuelve en el campo `name` de los metadatos | `DocumentMapper:111-118` | API3 |
| SEC-049 | High | `deleteDocument` sin verificación de titularidad ni de existencia | `DocumentManagementAdapter:200-215` | API1 |
| SEC-050 | Medium | El path variable determina el verbo HTTP hacia el proveedor | `QurableServiceAdapter:80-92,169-178` | API8 |
| SEC-051 | Medium | Campos cruzados en `FileEntity`: `customerId` guarda el id del documento | `FileEntity:18-36`, `DocumentMapper:71-90` | — |
| SEC-052 | Low | Endpoints declarados que responden 501 | Contratos + delegates | API9 |

### Nota sobre SEC-051

`FileEntity` tiene los nombres cruzados respecto a lo que almacena:

| Campo Java | Atributo DynamoDB | Contenido real |
|---|---|---|
| `customerId` | `id` (partition key) | **UUID del documento** |
| `name` | `filename` (sort key) | **`ownerId` del titular** |
| `fileName` | — | Nombre real del fichero |

No es explotable por sí solo, pero es una trampa: al implementar la comprobación de titularidad de SEC-002, lo natural es comparar contra `customerId` —y eso no valida nada—. La comprobación debe hacerse contra `name`.

Se documenta precisamente porque induce a error: durante esta misma revisión se interpretó mal en una primera lectura.

---

## 5. Qué NO verá el Ethical Hacking

Sin acceso al código ni a los logs, estos hallazgos quedan fuera del alcance. **Siguen siendo reales y siguen requiriendo corrección**, pero no aparecerán en el informe del proveedor:

| Hallazgo | Por qué no lo verá |
|---|---|
| SEC-001 Autenticación desactivada | El gateway filtra antes de llegar |
| SEC-003 18 secretos versionados | Sin acceso al repositorio |
| SEC-004 TLS trust-all | Es tráfico saliente, no observable desde el consumidor |
| SEC-006 Callback a `webhook.site` | No verá la petición al proveedor de firma |
| SEC-007/011/012/013 Fugas en logs | Sin acceso al agregador |
| SEC-008 DNI reales en `data.sql` | Sin acceso al repositorio |
| SEC-016 Ausencia de timeouts | Solo indirectamente, bajo carga |
| SEC-017 Reintentos no idempotentes | Requiere provocar fallo del proveedor |
| SEC-023 Debilidades del JWT emitido | Es un token saliente |
| SEC-034 Dependencias | Sin acceso al build |

**Un EH limpio no equivale a un código seguro.** De los 46 hallazgos, unos 20 son observables desde fuera; el resto solo se detecta con acceso al código, que es justamente lo que ya se hizo.

---

## 6. Priorización antes del Ethical Hacking

Ordenada por probabilidad de detección × impacto en el informe del proveedor.

### Bloque 1 — Lo que Arquitectura ya anticipó

Tres de las cinco pruebas que Dennis describió sin haber visto el informe:

| # | Acción | Hallazgos | Esfuerzo |
|---|---|---|---|
| 1 | Comprobación de titularidad en `bedocmanagement` y `beproducoffering` | SEC-002, SEC-047, SEC-049 | 2-3 días |
| 2 | Validar MIME con Tika siempre + sanear clave S3 | SEC-015 | 1 día |
| 3 | Autenticar el tramo entre microservicios | SEC-021 | 2 días |

### Bloque 2 — Detección trivial, corrección de horas

| # | Acción | Hallazgos | Esfuerzo |
|---|---|---|---|
| 4 | `getDocumentVersion` por clave en vez de `findAll()` | SEC-014 | 30 min |
| 5 | No devolver el `ownerId` en el campo `name` | SEC-048 | 30 min |
| 6 | Unificar respuesta ante recurso inexistente (404 en los tres) | SEC-047 | 1 h |
| 7 | Manejador `Exception` en los `ControllerAdvice` | SEC-028 | 2 h |
| 8 | Eliminar la rama `CONTRATO_CLIENTE` | SEC-032 | 20 min |
| 9 | Cerrar Swagger y actuator en `pre`/`pro` | SEC-022, SEC-025 | 30 min |

### Bloque 3 — Requiere decisión

| # | Acción | Hallazgos | Nota |
|---|---|---|---|
| 10 | Rediseño del flujo OTP | SEC-005 | Cambio de contrato: confirmar viabilidad |
| 11 | Eliminar el fail-open de reclamos | SEC-010 | Definir comportamiento ante fallo del proveedor |
| 12 | Corregir la semántica de `validate_status` | SEC-040 | Consultar con negocio y con Gesintel |

**El bloque 2 completo cabe en una jornada** y elimina seis hallazgos del informe del proveedor.

---

## 7. Recomendación sobre el alcance del EH

Merece la pena plantear a Arquitectura dos cosas:

1. **Incluir un escenario de red interna.** Sin él, SEC-001 y SEC-021 no se prueban, y son precisamente los que sostienen el resto del modelo de seguridad. Un supuesto de "contenedor comprometido" es práctica habitual en banca.

2. **Que el informe del proveedor deje constancia del alcance.** Si la autenticación se prueba solo a través del gateway, conviene que el informe lo diga explícitamente, en lugar de concluir "autenticación correcta". Evita que un aprobado se interprete como una garantía que no cubre.

---

*Anexo derivado de `SECURITY_CODE_REVIEW.md` v1.3 y del re-escaneo del 2026-08-24 con criterio de observabilidad externa. Los hallazgos SEC-047 a SEC-052 son nuevos y deben incorporarse al informe principal y a la línea base.*
