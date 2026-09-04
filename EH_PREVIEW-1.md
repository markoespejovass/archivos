# Vista previa del Ethical Hacking

**Anexo de `SECURITY_CODE_REVIEW.md` v1.7** · 2026-08-24, **actualizado el 2026-09-03**
**Propósito:** anticipar qué encontrará la empresa que ejecute el Ethical Hacking, para poder cerrarlo antes.

Este documento **no sustituye al informe completo**. Filtra sus 56 hallazgos — **47 en alcance tras la revisión de §1.1 del informe** — por un único criterio —*¿es observable desde fuera?*— y añade los que aparecieron al re-escanear el código con esa lente.

> ### Revisión de alcance (v1.7)
>
> A petición del equipo quedan **fuera de este Ethical Hacking**:
>
> * **`cpe-nxhbsc-becustombeprogrm`** (SKY y Qurable) — componente completo.
> * **`cpe-nxhbsc-lmauthorizer`** — proyecto completo.
> * **`cpe-nxhbsc-bedigitsignature`, solo la recepción** — entra el API de **solicitud** de firma; queda fuera el **callback** de retorno.
>
> Nueve hallazgos pasan a **`APLAZADO`** (SEC-006, SEC-016, SEC-017, SEC-023, SEC-024, SEC-031, SEC-050, SEC-055, SEC-057). **No se eliminan**: siguen abiertos como deuda técnica, solo salen del cómputo de esta prueba. Efecto sobre este anexo:
>
> * **CP-10 deja de ser un caso ejecutable** (dependia por completo de SEC-050, en `becustombeprogrm`). Los 17 restantes siguen vigentes.
> * **CP-18 no se ve afectado** y sigue siendo el caso de mayor valor de la lista.
> * De los hallazgos observables desde fuera, el recuento baja de 22 a **21**.
> * **SEC-006 merece una nota.** Se aplaza porque el callback es recepción, pero la URL de retorno hacia `webhook.site` **la envía el API de solicitud, que sí está en alcance**. El proveedor no lo verá desde fuera — nunca lo vio —, pero el efecto se dispara con un endpoint que sí se va a probar.
>
> ### Actualización del 2026-09-03
>
> Re-verificados los 55 hallazgos del 31-ago contra la entrega del 3-sep, que refresca seis proyectos (§24 del informe). Para la preparación del Ethical Hacking, cuatro consecuencias:
>
> * **Aparece CP-18, y es el caso de mayor valor de toda la lista.** `POST /search_documents` con `keyValue: ""` devuelve el inventario documental completo del sistema y el DNI de cada titular, en una sola petición autenticada. Sustituye a CP-02+CP-03 como camino más corto al mismo objetivo.
> * **CP-02 y CP-05 pierden fuerza.** El endpoint de versiones dejó de devolver la tabla completa (SEC-014 resuelto) y el borrado ya no es alcanzable desde el contrato (SEC-049). El proveedor no los reportará.
> * **CP-16 se simplifica hasta lo trivial.** No hace falta fuerza bruta: `validCode` responde `PROCESSED` ante cualquier código presente en la tabla, porque el veredicto que el proveedor de OTP devuelve se calcula y se descarta.
> * **Ningún caso del bloque crítico se ha cerrado.** CP-01 (BOLA), CP-03, CP-04 y CP-06 siguen exactamente igual, verificados línea a línea. **Los siete hallazgos Critical del informe siguen abiertos.**
>
> ### Actualización del 2026-08-31
>
> Se han re-verificado los 52 hallazgos de la línea base del 24-ago contra el código actual (§23 del informe). Para la preparación del Ethical Hacking, tres consecuencias:
>
> * **CP-12 ha dejado de ser un caso viable.** Los contratos se han recortado de 67 operaciones declaradas a 43, y de ~26 respuestas 501 quedan 5. El inventario fantasma que el proveedor habría usado como mapa ya casi no existe.
> * **Aparecen dos casos nuevos**, CP-16 y CP-17, derivados de correcciones aplicadas en este ciclo.
> * **Ningún caso del bloque crítico se ha cerrado.** CP-01 (BOLA), CP-02, CP-03, CP-05 y CP-06 siguen exactamente igual, verificados línea a línea. La lista de prioridades de §6 sigue vigente sin un solo tachado.

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
| **API1 — Broken Object Level Authorization** | **Sí, casi con certeza** | SEC-002, **SEC-058**, SEC-047 · *SEC-049 sale: ya no es alcanzable* |
| **API2 — Broken Authentication** | Parcialmente (el gateway lo tapa) | SEC-005 sí · **SEC-053** sí · SEC-001 no |
| **API3 — Broken Object Property Level Authorization** | **Sí** | SEC-048 (vía `searchMapper`), **SEC-058** |
| **API4 — Unrestricted Resource Consumption** | **Sí** | SEC-019, SEC-020, SEC-039, **SEC-058**, SEC-053 · *SEC-014 sale: resuelto* |
| **API5 — Broken Function Level Authorization** | Posible | SEC-021 |
| **API6 — Unrestricted Access to Sensitive Business Flows** | **Sí** | SEC-005, SEC-019, SEC-037 |
| **API7 — Server Side Request Forgery** | No | Analizado y descartado (§14) |
| **API8 — Security Misconfiguration** | Depende del gateway | SEC-022, SEC-025, SEC-028, SEC-030, **SEC-056** |
| **API9 — Improper Inventory Management** | Reducido desde v1.5 | SEC-046, SEC-052 *(5 endpoints 501; `bedocmanagement` añade 3)* |
| **API10 — Unsafe Consumption of APIs** | **Sí** | SEC-018, SEC-040 |

Nueve de diez categorías tienen al menos un hallazgo asociado. La única limpia es SSRF, verificada y descartada.

---

## 3. Casos de prueba y resultado esperado

Ordenados por probabilidad de que el proveedor los ejecute. **18 casos** tras la actualizacion del 3-sep. Cada uno corresponde a una prueba que Arquitectura ya anticipó o a un caso estándar del marco OWASP.

### CP-01 · Token válido, identificador de otro cliente → **BOLA**

> Anticipado por Arquitectura: *"el token va a tener otro usuario, va a tener otro AP"*

```http
GET /v1/customer_card_position/list?customer_id=<cliente ajeno>
Authorization: Bearer <token válido del atacante>
```

**Resultado esperado: 200 con la posición de tarjetas del otro cliente.** El gateway lo acepta porque el token es válido; el pod no comprueba titularidad.

Repetible en: `becreditrisk` (`documentNumber` en el cuerpo), `bedatacomanagment` (`party_id`), `bedocmanagement` (`document_id`), `beknowyocustomer` (`questionnaire_id`), `becustombeprogrm` (`key`).

**Hallazgo:** SEC-002 · **API1** · Es el hallazgo más probable y más grave del EH.

### CP-02 · Enumeración diferencial de documentos ← *reducido el 3-sep*

Tres endpoints responden distinto ante el mismo identificador inexistente:

| Petición | Documento existe | No existe |
|---|---|---|
| `POST /download_document` | 200 + URL | **404** |
| `GET /documents/{id}` | 200 + metadatos | **200 + objeto vacío** |
| `DELETE /documents/{id}` | 204 | **204** |

La diferencia 404 / 200-vacío permite **enumerar qué identificadores existen** sin necesidad de acceder a ellos. Es el primer paso de cualquier ataque sobre objetos.

> **Actualización del 3-sep.** La fila `DELETE` ya no aplica: la operación no está declarada en el contrato ni implementa ningún delegate (SEC-049). Y el oráculo pierde casi todo su valor práctico frente a **CP-18**, que obtiene directamente la lista de identificadores válidos sin necesidad de enumerar. El proveedor probablemente lo reporte igual, pero como hallazgo menor.

**Hallazgo:** SEC-047 · **API1**

### CP-03 · DNI del titular expuesto en los metadatos ← *nuevo*

```http
GET /v2/document_management/documents/{document_id}
```

> **Actualización del 3-sep — corregido a medias.** `getMapper` ya devuelve `entity.getFileName()`, de modo que **este endpoint concreto ya no expone el DNI**. Pero `searchMapper`, en el mismo fichero, sigue haciendo `wrapper.setName(objectSumary.getName())` — y ese es el método que sirve `POST /search_documents`, que devuelve muchos registros por llamada. La prueba a ejecutar ya no es esta: es **CP-18**.

`DocumentMapper.searchMapper()` construye cada resultado con `wrapper.setName(objectSumary.getName())`, y `FileEntity.name` contiene el `ownerId` del titular (lo fija `toEntity:78-82`). **El campo `name` de cada resultado de búsqueda devuelve el documento de identidad del titular.**

Encadenado con CP-18, se obtiene el repositorio documental completo y el DNI del titular de cada pieza en una única petición.

**Hallazgo:** SEC-048, SEC-058 · **API3**

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

### CP-05 · Borrado sin verificación ← *cerrado como caso ejecutable el 3-sep*

```http
DELETE /v2/document_management/documents/{document_id}
```

> **Actualización del 3-sep — el proveedor NO reproducirá este caso.** `removeDocument` no lleva `@Override`, no corresponde a ningún método de los delegates que la clase implementa, y el contrato `openapi.yaml` no declara ninguna operación `DELETE`. No hay controlador generado que lo invoque: la ruta devolverá 404 del propio framework. El método además ya comprueba existencia.
>
> **Se conserva el caso por una razón:** el código sigue sin verificar titularidad, y basta con declarar la operación en el contrato — cinco líneas de YAML — para que vuelva a ser explotable. Si en algún momento se publica ese `DELETE`, esta prueba debe volver a la lista activa el mismo día.

`deleteDocument` no comprueba titularidad. Un tercero con token válido eliminaría el objeto de S3 y su registro.

**Hallazgo:** SEC-049 (Low desde v1.6) · **API1**

### CP-06 · Abuso del flujo de OTP

```http
POST /v1/emailboxes/{emailbox_id}/send_email      → genera OTP al destinatario indicado
POST /v1/emailboxes/{id}/emails/{OTP}/classify_email → valida sin comprobar de quién es
```

`validCode` busca el OTP como clave primaria en DynamoDB, sin vincularlo a usuario ni operación, y la condición de éxito es `status != null`.

**Cambio verificado el 31-ago:** se ha añadido un rate limiter (3 peticiones / 15 min por dirección de correo) **solo en la generación**. La validación sigue sin límite alguno. Para el proveedor esto significa que el segundo intento de `send_email` sobre el mismo destinatario devolverá `429 TL0019` —lo interpretará, correctamente, como un control existente— mientras que `classify_email` admite intentos ilimitados.

Tres vectores, de los cuales dos siguen abiertos: OTP propio para autorizar operación ajena · **fuerza bruta sobre la validación** · abuso de envío de correo a destinatarios **distintos** (el límite es por destinatario, así que cada dirección estrena cupo).

**Hallazgos:** SEC-005, **SEC-053** · **API2, API6**

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

> **APLAZADO en v1.7 — este caso no se ejecuta.** Depende por completo de `cpe-nxhbsc-becustombeprogrm`, fuera del alcance de este EH. Se conserva para cuando el componente vuelva a alcance.

**Hallazgo:** SEC-050 · **API8** · ⏸️ fuera de alcance

### CP-11 · Fail-open en el Libro de Reclamaciones

```http
POST /v1/claims_book/claims
```

Si el proveedor falla, `ClaimsAdapter.createClaims` devuelve **200 OK con `complaintBookId: "56782902"` fijo**. `getClaims` devuelve datos de una persona ficticia (`documentNumber: "12345678"`).

Detectable comparando respuestas: el mismo identificador constante en peticiones distintas lo delata de inmediato.

**Hallazgo:** SEC-010 · **API8** · Impacto regulatorio (INDECOPI)

### CP-12 · Superficie declarada no implementada ← *muy reducido el 31-ago*

**Corregido en gran parte.** Los contratos se han recortado: `beknowyocustomer` pasa de 20 operaciones declaradas a 3 y `bedatacomanagment` de 8 a 1. El total del programa baja de **67 declaradas / ~26 implementadas** a **43 / 38**.

Quedan cinco endpoints que responden `501`:

| Proyecto | Operación |
| -------- | --------- |
| `bedocmanagement` | `PUT /documents/{document_id}` |
| `bedocmanagement` | `POST /documents/{document_id}/consolidate` |
| `bedocmanagement` | `POST /update_document` |
| `beknowyocustomer` | `GET /create` |
| `beemailboxes` | `GET /health` |

Sigue siendo reportable como **API9**, pero ha dejado de ser un hallazgo de peso: cinco endpoints no son un inventario fantasma.

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

### CP-16 · Validación de OTP que acepta cualquier código ← *simplificado el 3-sep*

> **Actualización del 3-sep — ya no hace falta fuerza bruta.** `JsonApiClient.validOTP` se reescribió para evaluar de verdad el veredicto de Celmedia (`status == "validated" && isValid()`), pero `OTPServiceAdapter:66` sigue comprobando `status != null` y el método nunca devuelve `null`. **Cualquier código presente en la tabla — el de cualquier usuario — responde `PROCESSED`, aunque no sea el correcto para la operación.** El proveedor lo detectará en el primer intento, no en el milésimo.

El limitador añadido en el ciclo anterior cubre la generación y no la validación:

```http
POST /v1/emailboxes/{id}/emails/00000001/classify_email     → sin límite
POST /v1/emailboxes/{id}/emails/00000002/classify_email     → sin límite
…
Authorization: Bearer <token válido de Cognito>
```

Dos matices que el proveedor detectará y que conviene entender antes:

* **El espacio a recorrer no es el del OTP de una operación**, sino el de *cualquier* OTP vivo en la tabla: `validCode` busca el código como clave primaria y da por buena cualquier respuesta no nula. Cuantos más usuarios estén operando a la vez, menos intentos hacen falta.
* **El limitador es por pod y crece sin cota.** `rateLimiterRegistry.rateLimiter("otp:" + email)` crea una entrada por dirección y nunca la elimina; enviar peticiones con direcciones distintas hace crecer el heap. Es también un caso de agotamiento de recursos (API4).

**Hallazgos:** SEC-053, SEC-005 · **API2, API4, API6** · Es el caso nuevo con más probabilidad de aparecer en el informe del proveedor.

### CP-17 · `PATCH` de consentimiento: 500 sistemático ← *nuevo (31-ago)*

```http
PATCH /v7/data_consents_management/parties/{party_id}/consent_agreements/{consent_id}
Authorization: Bearer <token válido>
```

Se intentó corregir SEC-030 añadiendo una comprobación de existencia, pero la escritura sigue usando `putIfAbsent` (condición `attribute_not_exists`). Las dos ramas quedaron mutuamente excluyentes: si el consentimiento no existe salta una excepción; si existe, DynamoDB rechaza la escritura y el cliente recibe **500 con `TL9999`**.

El proveedor lo reportará como error no controlado (**API8**) y, si su alcance incluye lógica de negocio, también como fallo funcional de una operación con implicaciones regulatorias: no hay forma de revocar un consentimiento.

> Nota de alcance: la operación **ya no figura en el contrato OpenAPI** de `bedatacomanagment`, que hoy declara solo `POST /consent_agreements`. Si el API Gateway publica únicamente lo declarado, el proveedor no llegará a este endpoint — pero el código sigue ahí y sigue roto.

**Hallazgo:** SEC-030 · **API8**

### CP-18 · Volcado del inventario documental completo ← *nuevo (3-sep)* — **el caso de mayor valor de esta lista**

```http
POST /v2/document_management/search_documents
Authorization: Bearer <token válido de Cognito>
Content-Type: application/json

{
  "searchParameters": {
    "discriminator": "OR",
    "searchProperties": [
      { "keyId": "NAME", "keyOperator": "CONTAINS", "keyValue": "" }
    ]
  }
}
```

**Resultado esperado: 200 con todos los documentos del sistema.** En DynamoDB, `contains(attr, "")` es cierto para toda cadena, de modo que el `filterExpression` no filtra nada y `BaseDynamoRepository.search()` recorre la tabla entera — sin `Limit`, sin paginación. Cada resultado trae `documentId`, `mimeType` y un campo `name` que **es el DNI del titular** (`searchMapper:49`).

Con esa lista, cada `documentId` alimenta directamente:

```http
POST /v2/document_management/download_document
{ "document": { "documentId": "<id obtenido del volcado>" } }
```

que devuelve una URL prefirmada de S3 válida 10 minutos y **tampoco comprueba titularidad**.

Por qué este caso es el que más pesará en el informe del proveedor:

* **No requiere adivinar nada.** CP-01 y CP-02 exigen conocer o enumerar identificadores ajenos; aquí el sistema los entrega.
* **Ninguna capa del perímetro interviene.** La petición está autenticada, es válida contra el contrato OpenAPI y su cuerpo no contiene ningún patrón que un WAF pueda marcar.
* **Es una sola petición.** No hay volumen anómalo que dispare una alerta.
* **Mezcla tres categorías OWASP a la vez**, lo que en la práctica multiplica su severidad en cualquier informe: API1 (autorización de objeto), API3 (propiedad `name` con PII) y API4 (Scan sin cota sobre la tabla completa).

**Mitigación de 30 minutos si no llega la corrección de fondo:** rechazar `keyValue` vacío o de menos de 3 caracteres en `FileSearchMapper`, y añadir `.limit(N)` al `ScanEnhancedRequest`. No cierra el hallazgo — sigue siendo posible barrer por prefijos — pero convierte un volcado silencioso en una campaña ruidosa y detectable.

**Hallazgos:** SEC-058, SEC-002, SEC-039, SEC-048 · **API1, API3, API4**

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

### Hallazgos nuevos del re-escaneo del 31-ago

| ID | Severidad | Hallazgo | Componente | OWASP | ¿Lo verá el EH? |
|---|---|---|---|---|---|
| SEC-053 | High | El rate limiter de OTP cubre la generación pero no la validación; registro sin cota | `EmailboxIdInputPort:39-70` | API2, API4 | **Sí** — CP-16 |
| SEC-054 | High | Dos servicios asumen el rol IAM de otro servicio | `application-*.yml` `role-arn` | API8 | No — requiere acceso al repositorio o a la cuenta AWS |
| SEC-055 | High | El chart de `pro` lee un secreto de `dev-publickey-nexhub` | `.gluon/cd/pro/values-pro.yaml:37-42` | API8 | No — requiere acceso a los manifiestos |
| SEC-056 | Medium | Valores de relleno como defecto de variables en `pre`/`pro` | `application-pro.yml` | API8 | Indirectamente, si alguna variable falta en el despliegue |
| SEC-057 | Info | El proyecto del Lambda Authorizer existe pero está vacío | `lmauthorizer` | — | No — pero **condiciona la lectura del resultado**, ver §1.2 |

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

| SEC-054 Rol IAM cruzado | Es configuración de despliegue, no comportamiento observable |
| SEC-055 Secreto de `dev` en `pro` | Sin acceso a los manifiestos ni al namespace |

**Un EH limpio no equivale a un código seguro.** De los 55 hallazgos, unos 22 son observables desde fuera; el resto solo se detecta con acceso al código y a los manifiestos, que es justamente lo que ya se hizo.

**Y hay un caso peor que "no lo verá": lo verá y lo dará por bueno.** El rate limiter de `beemailboxes` devuelve `429` en el flujo de envío de OTP. Un proveedor que pruebe únicamente ese flujo concluirá que existe protección contra fuerza bruta sobre el segundo factor. No existe: la validación, que es donde se fuerza el código, no tiene ninguna (SEC-053, CP-16). Conviene señalarle explícitamente que pruebe `classify_email`, no solo `send_email`.

---

## 6. Priorización antes del Ethical Hacking

Ordenada por probabilidad de detección × impacto en el informe del proveedor.

> **Estado al 3-sep.** De las doce acciones de esta sección **sigue sin completarse ninguna de las del bloque 1 y el bloque 3**. Del bloque 2 se ha cerrado una (el listado de versiones, SEC-014) y una se ha quedado a medias (el DNI en los metadatos, SEC-048: corregido en `getMapper`, pendiente en `searchMapper`). Se ha añadido **CP-18**, que sube al primer puesto de la lista de prioridades: es el único caso que expone datos personales de todos los clientes en una sola petición, y su mitigación parcial cuesta media hora.
>
> Antes de la prueba, y por orden de coste/beneficio: **(1)** dos líneas — `if ("Valid".equals(status))` en `OTPServiceAdapter:66` y `setName(getFileName())` en `DocumentMapper:49` — cierran la observabilidad externa de CP-16 y CP-03; **(2)** media hora en `FileSearchMapper` degrada CP-18 de volcado a barrido detectable.

> **Estado al 31-ago.** Ninguna de las doce acciones de esta sección se ha completado. Sí se han cerrado, en cambio, tres cosas que no estaban en la lista: los contratos (que desactiva casi por completo CP-12), la validación TLS de `beemailboxes` y los datos personales de `data.sql` — ninguna de las tres observable desde fuera. El bloque 2, que sigue siendo el de mejor relación coste/beneficio de cara al informe del proveedor, está intacto.

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
| 13 | **Confirmar el estado del Lambda Authorizer** | SEC-057 | Si el autorizador previsto no está implementado, cambia la calibración de todo el informe |

**El bloque 2 completo cabe en una jornada** y elimina seis hallazgos del informe del proveedor.

---

## 7. Recomendación sobre el alcance del EH

Merece la pena plantear a Arquitectura dos cosas:

1. **Incluir un escenario de red interna.** Sin él, SEC-001 y SEC-021 no se prueban, y son precisamente los que sostienen el resto del modelo de seguridad. Un supuesto de "contenedor comprometido" es práctica habitual en banca.

2. **Que el informe del proveedor deje constancia del alcance.** Si la autenticación se prueba solo a través del gateway, conviene que el informe lo diga explícitamente, en lugar de concluir "autenticación correcta". Evita que un aprobado se interprete como una garantía que no cubre.

3. **Que el escenario interno cubra la identidad IAM, no solo la red** *(añadido el 31-ago)*. La revisión ha encontrado que dos servicios asumen el rol IAM de otro (SEC-054) y que cuatro montan el token del ServiceAccount en el contenedor (SEC-043). La combinación permite que un pod comprometido alcance el bucket documental o la tabla de OTP **sin llamar a ningún otro microservicio** — es decir, sin cruzar la frontera que un escenario de red interna estaría vigilando. Está documentada como cadena CH-6 en el informe. Si se incluye el supuesto de contenedor comprometido, conviene pedir expresamente que se enumeren los permisos efectivos del rol asumido.

---

---

## 8. Mapa completo: qué hallazgos impactan al Ethical Hacking

Tabla canónica de los 55 hallazgos vivos de `SECURITY_CODE_REVIEW.md` v1.5 frente a un único criterio: **¿lo verá el proveedor desde el API Gateway con un token válido?**

Esta tabla es la fuente de la columna `EH` de la hoja *Hallazgos* del Excel ejecutivo. Si se modifica aquí, hay que regenerar el libro (ver el pie de sección).

### Criterio de clasificación

| Valor | Significado |
|---|---|
| **SÍ** | Observable desde fuera con las credenciales que el equipo entregará. El proveedor lo encontrará si prueba el caso indicado |
| **PROBABLE** | Observable, pero condicionado a qué publique el gateway o a la profundidad de la prueba |
| **SOLO INTERNO** | Únicamente si el alcance incluye el escenario de red interna o contenedor comprometido (§7) |
| **ENMASCARADO** | El perímetro lo tapa **y su ausencia se leerá como aprobado**. Es el caso más delicado del informe |
| **NO** | Requiere acceso al código, a los logs, a los manifiestos o al tráfico saliente |

### Distribución

| Valor | N.º | Peso |
|---|--:|---|
| SÍ | 21 | Incluye 1 Critical, 9 High · **entra SEC-058; salen SEC-014 (resuelto) y SEC-050 (aplazado)** |
| PROBABLE | 4 | Depende de la configuración del gateway |
| SOLO INTERNO | 2 | Solo con el escenario que §7 recomienda añadir |
| ENMASCARADO | 1 | SEC-001 — el más importante del informe |
| NO | 19 | Reales y pendientes, pero fuera del alcance de la prueba |
| **APLAZADO** | **9** | Componentes excluidos del EH en v1.7. Siguen abiertos como deuda técnica |
| **En alcance** | **47** | |
| **Total trazable** | **56** | |

**Veintiuno de cuarenta y siete.** Si el proveedor entrega un informe con veinte hallazgos y el equipo lo interpreta como el estado de la plataforma, estará leyendo el 40 % del problema.

> **Matiz del 3-sep.** La proporción apenas se mueve, pero su composición sí: SEC-014 sale por resuelto y SEC-049 deja de ser ejecutable, mientras entra SEC-058 — que por sí solo cubre lo que antes exigía encadenar tres casos. **El informe del proveedor será previsiblemente más corto y más grave**: menos hallazgos, pero con un volcado de datos personales de todos los clientes entre ellos.

### Tabla

| ID | EH | Caso / OWASP | Por qué |
|---|---|---|---|
| SEC-001 | **ENMASCARADO** | §1.1 · API2 | El gateway devuelve 401 antes de llegar al pod. **El proveedor concluirá «autenticación correcta» sobre una capa que no existe** |
| SEC-002 | **SÍ** | CP-01, CP-18 · API1 | Token válido + identificador ajeno. El hallazgo más probable y más grave del EH |
| SEC-058 | **SÍ** | CP-18 · API1, API3, API4 | **Nuevo.** Una petición autenticada devuelve todos los documentos del sistema y el DNI de cada titular |
| SEC-059 | **NO** | — | Dato en reposo: requiere acceso a DynamoDB |
| SEC-003 | **NO** | — | Requiere acceso al repositorio |
| SEC-004 | **NO** | — | Es tráfico saliente: no observable desde el consumidor |
| SEC-005 | **SÍ** | CP-06, CP-16 · API2, API6 | `classify_email` responde `PROCESSED` ante cualquier OTP de la tabla: el veredicto del proveedor se calcula y se descarta |
| SEC-006 | **APLAZADO** | — | No verá la petición al proveedor de firma · **fuera del alcance del EH desde v1.7** |
| SEC-007 | **NO** | — | Requiere acceso al agregador de logs |
| SEC-009 | **NO** | — | Tráfico saliente hacia GSNET |
| SEC-010 | **SÍ** | CP-11 · API8 | El `complaintBookId` constante lo delata comparando dos respuestas |
| SEC-011 | **NO** | — | Requiere acceso al agregador de logs |
| SEC-012 | **NO** | — | Requiere acceso al agregador de logs |
| SEC-013 | **NO** | — | Requiere acceso al agregador de logs |
| SEC-014 | **RESUELTO** | — | Corregido en la entrega del 3-sep: `getDocumentVersion` consulta por clave. Sale del recuento; se conserva la fila por trazabilidad |
| SEC-015 | **SÍ** | CP-04 · API3, API4 | Subida de fichero con `mimeType` declarado por el cliente y clave S3 sin sanear |
| SEC-016 | **APLAZADO** | CP-08 · API4 | Solo indirectamente, bajo carga o provocando lentitud del proveedor · **fuera del alcance del EH desde v1.7** |
| SEC-017 | **APLAZADO** | — | Requiere provocar un fallo del proveedor y observar su lado · **fuera del alcance del EH desde v1.7** |
| SEC-018 | **SÍ** | CP-13 · API10 | Peticiones malformadas devuelven el cuerpo de error de SKY íntegro |
| SEC-019 | **SÍ** | CP-08 · API4 | Sin límite en 10 de los 11 servicios |
| SEC-020 | **SÍ** | CP-04, CP-08 · API4 | base64 de cientos de MB decodificado en memoria |
| SEC-021 | **PROBABLE** | CP-07 · API5 | Depende de que el gateway publique `download_document_intern` |
| SEC-022 | **PROBABLE** | API8 | Depende de si el gateway publica `/actuator`; con `show-details: ALWAYS` si lo hace |
| SEC-023 | **APLAZADO** | — | Es un token saliente hacia SKY/Zytrust · **fuera del alcance del EH desde v1.7** |
| SEC-024 | **APLAZADO** | — | Criptografía del payload de salida · **fuera del alcance del EH desde v1.7** |
| SEC-025 | **PROBABLE** | API8 | Depende de si el gateway publica `/swagger-ui` y `/v3/api-docs` |
| SEC-027 | **PROBABLE** | API8 | Manipular `X-Forwarded-*` es prueba estándar de cualquier proveedor |
| SEC-028 | **SÍ** | CP-09 · API8 | Cinco entradas válidas según contrato que producen 500 |
| SEC-029 | **NO** | — | Configuración de base de datos |
| SEC-030 | **SÍ** | CP-17 · API8 | 500 sistemático — *solo si el gateway publica el `PATCH`, que ya no está en el contrato* |
| SEC-031 | **APLAZADO** | — | Modelo interno de la tabla DynamoDB · **fuera del alcance del EH desde v1.7** |
| SEC-032 | **SÍ** | CP-15 · API8 | `CONTRATO_CLIENTE` aparece al fuzzear con diccionarios |
| SEC-033 | **NO** | — | Token saliente hacia Contáctanos |
| SEC-034 | **NO** | — | Requiere acceso al build |
| SEC-035 | **NO** | — | Control de flujo interno, inactivo en runtime |
| SEC-036 | **NO** | — | El XML es de salida hacia Celmedia, no de entrada |
| SEC-037 | **SÍ** | CP-06 · API6 | El replay de una operación sensible es prueba estándar |
| SEC-038 | **NO** | — | Se puede inyectar, pero el efecto solo se observa en el agregador de logs |
| SEC-039 | **SÍ** | CP-08 · API4 | Scan completo de DynamoDB por petición |
| SEC-040 | **SÍ** | CP-14 · API10 | Dos perfiles opuestos devuelven el mismo veredicto |
| SEC-041 | **NO** | — | Código muerto |
| SEC-042 | **NO** | — | Requiere acceso al repositorio |
| SEC-043 | **SOLO INTERNO** | CH-6 | Solo si el alcance incluye contenedor comprometido |
| SEC-044 | **SÍ** | API8 | Las cabeceras de respuesta son lo primero que revisa cualquier escáner |
| SEC-045 | **NO** | — | Fichero del classpath, no expuesto |
| SEC-046 | **SÍ** | CP-12 · API9 | Muy reducido tras el recorte de contratos: 43 declaradas / 38 implementadas |
| SEC-047 | **SÍ** | CP-02 · API1 | 404 frente a 200-vacío permite enumerar identificadores |
| SEC-048 | **SÍ** | CP-03 · API3 | El campo `name` de la respuesta devuelve el DNI del titular |
| SEC-049 | **SÍ** | CP-05 · API1 | `DELETE` sin titularidad, 204 en ambos casos |
| SEC-050 | **APLAZADO** | CP-10 · API8 | El path variable determina el verbo HTTP saliente · **fuera del alcance del EH desde v1.7** |
| SEC-051 | **NO** | — | Modelo interno; su valor es evitar una corrección mal dirigida de SEC-002 |
| SEC-052 | **SÍ** | CP-12 · API9 | Cinco endpoints devuelven 501 |
| SEC-053 | **SÍ** | CP-16 · API2, API4 | **Y hay riesgo de falso aprobado**: el 429 en `send_email` puede leerse como control de fuerza bruta que no existe en `classify_email` |
| SEC-054 | **SOLO INTERNO** | CH-6 · API8 | Requiere acceso a la cuenta AWS o a un contenedor comprometido |
| SEC-055 | **APLAZADO** | — | Requiere acceso a los manifiestos de despliegue · **fuera del alcance del EH desde v1.7** |
| SEC-056 | **NO** | — | Solo indirectamente, si alguna variable falta en el despliegue |
| SEC-057 | **APLAZADO** | — | No observable, pero **condiciona cómo debe leerse el resultado del EH** (§1.2) · **fuera del alcance del EH desde v1.7** |

### Cómo se propaga esta tabla al Excel

La columna `EH` de la hoja *Hallazgos* se genera a partir de esta tabla, no se escribe a mano. Tras regenerar el libro:

```bash
python build_exec_xlsx.py SECURITY_CODE_REVIEW.md SECURITY_CODE_REVIEW_EJECUTIVO_v1.5.xlsx
python aplicar_columna_eh.py EH_PREVIEW.md SECURITY_CODE_REVIEW_EJECUTIVO_v1.5.xlsx
python recalc_excel_win.py SECURITY_CODE_REVIEW_EJECUTIVO_v1.5.xlsx "Dashboard!C11"
```

`aplicar_columna_eh.py` está en este mismo directorio. Falla —en lugar de dejar huecos— si algún hallazgo del Excel no aparece en la tabla anterior, que es lo que garantiza que ambos documentos no se separen cuando aparezcan hallazgos nuevos.

---

*Actualizado el 2026-09-03 (v1.6): caso CP-18 nuevo — el de mayor valor de la lista —, CP-05 cerrado como caso ejecutable, CP-02 reducido, CP-03 y CP-16 reformulados, y hallazgos SEC-058 y SEC-059 incorporados. La comparativa completa está en §24 del informe principal.*

*Anexo derivado de `SECURITY_CODE_REVIEW.md`. Version original del 2026-08-24 (re-escaneo con criterio de observabilidad externa, hallazgos SEC-047 a SEC-052). Actualizado el 2026-08-31 con la re-verificación completa de la línea base: casos CP-16 y CP-17 nuevos, CP-12 muy reducido, y hallazgos SEC-053 a SEC-057 incorporados. La comparativa completa entre ambos escaneos está en §23 del informe principal.*
