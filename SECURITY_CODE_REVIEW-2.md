# Security Code Review

**Alcance:** `E:\claude\Santander\APIs\codigo`
**Tipo de revisión:** Secure Code Review + SAST manual + SCA + Threat Modeling + API Security Review
**Fecha:** 2026-09-03 (re-verificación completa, orientada a Ethical Hacking; alcance revisado el 2026-09-03) · **Auditoría inicial:** 2026-08-20
**Metodología:** 3 pasadas (reconocimiento → análisis profundo → correlación entre APIs y cadenas de ataque)
**Naturaleza:** revisión estática. No se ejecutó código, no se invocaron endpoints, no se utilizaron las credenciales encontradas.
**Insumo adicional:** diagrama de arquitectura PRE/PROD aportado por el equipo (ver §1.2), utilizado para calibrar la explotabilidad real de cada hallazgo.
**Documento vivo — versión 1.8.** Este informe se mantiene como base de trabajo para la remediación. El estado de cada hallazgo se registra en §20; el historial de cambios, al final del documento.

| Versión | Fecha | Cambio |
| ------- | ----- | ------ |
| 1.0 | 2026-08-20 | Versión inicial. 12 proyectos, 46 hallazgos. |
| 1.1 | 2026-08-20 | Incorporado el diagrama de arquitectura PRE/PROD. Recalibradas las severidades de SEC-009 (Critical→High) y SEC-025 (Medium→Low). Ampliados SEC-001, SEC-002, SEC-004 y SEC-006 con las fronteras de confianza reales. |
| 1.2 | 2026-08-20 | Excluido `cpe-nxhbsc-beemailsend` del alcance (plantilla sin código de negocio): 11 proyectos, 671 archivos Java, 67 operaciones. Reenfocado SEC-034 hacia la mezcla de líneas de Netty en `bedatacomanagment`. Añadida la guía de entorno de desarrollo sin Cognito en SEC-001. Añadido el seguimiento de remediación (§20). |
| 1.3 | 2026-08-21 | Congelada la linea base comparable `security-baseline-2026-08-20-v1.2.json` para el diff con futuras auditorias. Ver §21. |
| 1.4 | 2026-08-24 | Re-escaneo con criterio de **observabilidad externa**, tras conocerse que el Ethical Hacking será de caja negra a través del API Gateway. Seis hallazgos nuevos (SEC-047 a SEC-052). Total: 52. Nuevo anexo `EH_PREVIEW.md` (§22) con los 15 casos de prueba anticipados y su mapeo a OWASP API Top 10 2023. |
| 1.5 | 2026-08-31 | **Re-verificación completa de los 52 hallazgos contra el código actual**, con comparativa frente a `security-baseline-2026-08-24-v1.4.json` (§23). Dos hallazgos **resueltos** (SEC-008, SEC-026); cuatro con **bajada de severidad** (SEC-003, SEC-009, SEC-016, SEC-023) y cinco con **alcance reducido** sin cambiar de severidad (SEC-004, SEC-019, SEC-043, SEC-046, SEC-052); uno **empeora** (SEC-034) y uno tiene una **remediación incompleta** que deja el endpoint en 500 (SEC-030). Cinco hallazgos nuevos (SEC-053 a SEC-057), tres de ellos derivados de los propios cambios introducidos. Total: 55. Incorporado al alcance el proyecto `cpe-nxhbsc-lmauthorizer`. |
| 1.8 | 2026-09-04 | Añadido el anexo **`GUIA_REMEDIACION_EH.md`**: guía paso a paso, con código actual y código nuevo, de los **17 cambios que se pueden aplicar con alta confianza** sin decisiones de arquitectura ni de producto. Agrupados en cuatro PR. No modifica ningún hallazgo ni el alcance: es material de ejecución. Se documenta también, en su §0, por qué SEC-002 no puede cerrarse con esa guía. |
| 1.7 | 2026-09-03 | **Revisión de alcance a petición del equipo.** Quedan fuera del Ethical Hacking `cpe-nxhbsc-becustombeprogrm` (integraciones SKY y Qurable), `cpe-nxhbsc-lmauthorizer` y, dentro de `cpe-nxhbsc-bedigitsignature`, **la mitad de recepción** del flujo de firma (el callback de retorno); el API de solicitud sí entra. Los hallazgos **no se eliminan** —se conserva la trazabilidad completa— sino que pasan al estado **`APLAZADO`** y salen del cómputo. Nueve hallazgos aplazados (SEC-006, SEC-016, SEC-017, SEC-023, SEC-024, SEC-031, SEC-050, SEC-055, SEC-057) y once con alcance reducido. **Alcance efectivo: 47 hallazgos vivos**; el total con trazabilidad sigue siendo 56. |
| 1.6 | 2026-09-03 | **Re-verificación completa sobre la entrega del 3-sep**, que refresca seis proyectos (`becustombeprogrm`, `bedigitsignature`, `bedocmanagement`, `beemailboxes`, `beidentbiometric`, `beknowyocustomer`), con comparativa frente a `security-baseline-2026-08-31-v1.5.json` (§24). Un hallazgo **resuelto** (SEC-014); cinco **atenuados** por bajada de severidad (SEC-012, SEC-017, SEC-018, SEC-048 High→Medium; SEC-049 High→Low) y uno por alcance (SEC-043, 4→4 con tres correcciones nuevas y cinco proyectos que dejan de declararlo); uno **agravado** de Medium a High (SEC-056, tras eliminarse los perfiles `pre`/`pro`/`cert` de `bedigitsignature`). Dos hallazgos nuevos (SEC-058, SEC-059). **Dos remediaciones incompletas** que dejan el defecto en pie: la validación de OTP (SEC-005) y el DNI en los resultados de búsqueda (SEC-048). Total: 56. |

---

## 1. Executive Summary

### 1.1 Alcance analizado

Se analizaron **11 microservicios Spring Boot independientes** (Java 17, arquitectura hexagonal, controladores generados con `openapi-generator` y `delegatePattern`), pertenecientes al programa **NexHub / Proyecto NUBE Peru** (`com.santander.cpe.nxhbsc`), con **682 archivos fuente** y **42 operaciones REST declaradas** en contratos OpenAPI dentro del alcance (54 contando las 12 de la plantilla `beemailsend`; eran 43 en v1.5 y 67 en v1.4, ver SEC-046).

> ### Revisión de alcance (v1.7) — `cpe-nxhbsc-becustombeprogrm` aplazado
>
> A petición del equipo, quedan **fuera de este Ethical Hacking** dos componentes:
>
> * **`cpe-nxhbsc-becustombeprogrm`** — programas de beneficios de cliente, integraciones con **SKY** y **Qurable**.
> * **`cpe-nxhbsc-lmauthorizer`** — el proyecto del Lambda Authorizer del API Gateway.
> * **`cpe-nxhbsc-bedigitsignature`, solo la mitad de recepción** — entra en alcance el API de **solicitud** de firma (`POST /signature/signer` y todo lo que dispara: recuperación del documento, envío al proveedor); queda fuera la **recepción** del documento firmado, es decir el callback de retorno.
>
> **No se elimina del informe.** Sus hallazgos se conservan con su identificador, su evidencia y su remediación, y pasan al estado **`APLAZADO`** en el seguimiento (§20). El motivo es de trazabilidad: el componente existe, el código sigue desplegado y los defectos siguen ahí; lo que cambia es que no se prueban en este ejercicio. Tratarlos como resueltos, o borrarlos, produciría un histórico falso y haría que la próxima auditoría los reportara como hallazgos nuevos.
>
> | Efecto | Detalle |
> | ------ | ------- |
> | Hallazgos **aplazados** | 9 — `becustombeprogrm`: SEC-016, SEC-017, SEC-024, SEC-050, SEC-055 · `lmauthorizer`: SEC-057 · recepción de firma: SEC-006, SEC-023, SEC-031 · *(1 Critical, 1 High, 6 Medium, 1 Info)* |
> | Hallazgos con **alcance reducido** | 11 — siguen abiertos en el resto de servicios (ver columna Δ de §4) |
> | **Alcance efectivo del EH** | **47 hallazgos vivos** sobre **10 microservicios** y **37 operaciones** |
> | Total con trazabilidad | 56 hallazgos, 11 microservicios |
>
> Las cifras de este informe se dan a partir de aquí en las dos formas: **«en alcance»** (47) para dimensionar el Ethical Hacking, y **«total»** (56) para el seguimiento de la deuda técnica. Donde aparece una sola cifra, es la de alcance.
>
> **Cómo se ha trazado la frontera en firma digital.** El código no separa «solicitud» y «recepción» en dos artefactos, así que la línea se ha trazado por finalidad, y conviene que el equipo la valide:
>
> | Elemento | Lado | Hallazgos |
> | -------- | ---- | --------- |
> | `POST /signature/signer` → `DocumentProcessService.signtureDocument` | **Solicitud — en alcance** | SEC-021, SEC-037 |
> | `DocumentClient.getDocument` (recupera el PDF de `bedocmanagement`) | **Solicitud — en alcance** | SEC-011, SEC-032, SEC-021 |
> | `SignatureClient.signDocument` + `Util.handleError` | **Solicitud — en alcance** | SEC-018 (b) |
> | `Constant.CALLBACK` / `Constant.HEADERS` (URL y token del webhook de retorno) | **Recepción — aplazado** | SEC-006 |
> | `JwtUtil.generateToken()` (token que autentica el callback) | **Recepción — aplazado** | SEC-023 |
> | `Entity` + `saveDynamo` (guarda el JWT para casar el callback entrante) | **Recepción — aplazado** | SEC-031 |
> | Configuración del componente (TLS, wiretap, perfiles, rol IAM) | **Transversal — en alcance** | SEC-004, SEC-013, SEC-054, SEC-056 |
>
> **Un matiz de SEC-006 que no conviene que se pierda con el aplazamiento.** Ese hallazgo tiene dos mitades, y solo una es de recepción. La segunda —autenticar el callback con la cadena literal `jwt`— sí es puramente de recepción. Pero la primera —que la URL de retorno apunte a `webhook.site`, un servicio público de terceros— **la emite el API de solicitud, que sí está en alcance**: es `signtureDocument` quien envía esa URL al proveedor de firma, y la consecuencia (que el documento firmado acabe publicado en un tercero) se dispara con una llamada que el Ethical Hacking sí va a ejecutar. Se aplaza el hallazgo según lo pedido, pero **la corrección de esa URL no debería esperar al siguiente ciclo**: cuesta una propiedad de entorno y está en Quick Wins (§17, acción 2).
>
> **Una advertencia sobre SEC-057, que no conviene perder de vista.** El Lambda Authorizer vacío no es un hallazgo más: es el control compensatorio del que depende toda la calibración de SEC-001. Aplazarlo saca el hallazgo del informe del EH, pero **no cambia el hecho de que el authorizer del API Gateway no esté escrito en este repositorio**. Si el gateway se apoya en otro artefacto, conviene confirmarlo con Arquitectura antes de la prueba; si no, el perímetro descrito en §1.2 tiene un hueco en T3 que ninguna de las pruebas planificadas detectará.

> **Entrega analizada en v1.6.** Seis de los once proyectos se han refrescado el 3-sep-2026: `becustombeprogrm`, `bedigitsignature`, `bedocmanagement`, `beemailboxes`, `beidentbiometric` y `beknowyocustomer`. Los cinco restantes (`beclaims`, `becreditrisk`, `bedatacomanagment`, `beproducoffering`, `bewatchscreening`) conservan el código de la revisión anterior y se han re-verificado igualmente línea a línea. Todos los movimientos de esta versión se concentran, por tanto, en los seis proyectos modificados — con una excepción que conviene señalar: **ninguno de los siete hallazgos Critical se ha cerrado**, ni en los proyectos tocados ni en los intactos.

> **Exclusion del alcance.** El directorio contiene dos proyectos mas que no generan hallazgos propios, ambos **plantillas sin codigo de negocio**:
>
> * `cpe-nxhbsc-beemailsend` (solo un `sayHello()`). Se conserva una unica referencia a el, en SEC-001, por su valor probatorio: al ser la plantilla original intacta, evidencia cual era la configuracion de seguridad de partida antes de que los once proyectos reales la modificaran.
> * `cpe-nxhbsc-lmauthorizer` **(nuevo en v1.5)**, plantilla Gluon de Lambda Node.js: 17 ficheros, `src/helloworld.js` con un `console.log`, `deployment.yml` con los valores de ejemplo (`myBucket`, `myLambdaName`, `111222333444`) sin sustituir. Por su nombre es el **Lambda Authorizer** del API Gateway. Que exista vacio es informacion relevante, no ruido: el control compensatorio del que depende toda la calibracion de SEC-001 todavia no esta escrito. Se documenta como SEC-057.

Todos comparten la misma plantilla corporativa Gluon (`santander-spring-boot-starter-parent`), el mismo `Dockerfile`, los mismos workflows de CI/CD y — lo que resulta determinante para este informe — **la misma configuración de seguridad**.

### 1.2 Arquitectura de despliegue y fronteras de confianza

Según el diagrama de arquitectura PRE/PROD facilitado, el flujo de entrada es:

```text
App Móvil (+ SDK FacePhi)
   ↓
Conexa  ──►  Akamai  ──►  Imperva  ──►  AWS WAF  ──►  API Gateway
                              │                            │
                              └──► AWS WAF ──► Amazon Cognito
                                   (AWS LandingZone)        │
                                                            ▼
                                                    AWS PrivateLink
                                                            ▼
                                                    NLB (VPC, AZ)
                                                            ▼
                                        ┌───────── Private Subnet (EKS) ─────────┐
                                        │ KYC · Oferta Producto · Reclamos       │
                                        │ Watchlist Screening · Firma Digital    │
                                        │ Registro SKY · Data Consent Mgmt       │
                                        │ Gestión Documental · Orquestación      │
                                        │ Riesgo Crédito · Ident. Biométrica     │
                                        │ Notificaciones Correo                  │
                                        └────────────────────────────────────────┘
                                                            │
                        ┌───────────────────────────────────┴──────────────────┐
                        ▼                                                      ▼
            Transit Gateway → Firewall Norte                     Transit Gateway → Firewall Sur
                        ▼                                                      ▼
                    Netskope                                                 GSNET
                        ▼                                                      ▼
      Terceros: GDS Modellica, FacePhi, Gesintel,              Sistemas Santander (Navarrete interno):
      Celmedia, Aerolínea (SKY), Puntos (Qurable)              Sistema Contáctanos

            Datos: AWS WL Account → DynamoDB · S3 · RDS
            Plataforma: Secrets Manager · KMS · ECR (AWS EKS Account)
```

**Fronteras de confianza identificadas:**

| # | Frontera | Quién autentica | Quién autoriza | Verificable en código |
| - | -------- | --------------- | -------------- | --------------------- |
| T1 | Internet → Conexa/Akamai/Imperva | Imperva (WAF/bot) | — | No |
| T2 | Imperva → AWS WAF → Cognito | **Amazon Cognito** | Cognito (autenticación) | No |
| T3 | Cognito → API Gateway | API Gateway (authorizer) | Scopes/rutas del gateway | No |
| T4 | API Gateway → PrivateLink → NLB → **pod** | **Nadie** | **Nadie** | **Sí — SEC-001** |
| T5 | **pod → pod** (este-oeste, misma subred) | **Nadie** | **Nadie** | **Sí — SEC-001, SEC-021** |
| T6 | pod → Netskope → terceros | API key / OAuth2 / Basic | Proveedor | Sí — SEC-003, SEC-004 |
| T7 | pod → GSNET → Contáctanos | Usuario/contraseña, **HTTP en claro** | Contáctanos | Sí — SEC-009 |
| T8 | pod → AWS (DynamoDB/S3/RDS) | IRSA + STS AssumeRole | Política IAM del rol | Sí — control correcto |

Este diagrama **mejora sustancialmente la postura frente a Internet** respecto a lo que sugiere el código aislado: los pods viven en subred privada, tras PrivateLink, tras un API Gateway con autorizador Cognito, tras dos capas de WAF y un CDN con protección de bots. Las severidades de este informe están calibradas teniendo en cuenta ese perímetro.

Lo que el perímetro **no** resuelve, y que sigue siendo responsabilidad del código:

* **Autorización a nivel de objeto (T4).** Cognito autentica *quién* llama, pero no puede saber si el `customer_id`, `party_id` o `document_id` que el solicitante pide le corresponde. Esa decisión solo puede tomarse en el microservicio, y **ningún microservicio la toma** porque ninguno lee el token (SEC-002).
* **Tráfico este-oeste (T5).** Los once servicios comparten subred privada. Un pod comprometido —o cualquier workload con ruta al NLB— invoca a los demás **sin pasar por Imperva, WAF, Cognito ni API Gateway**. En ese plano no hay ningún control (SEC-001, SEC-021).
* **Defensa en profundidad.** El backend descarta el JWT de Cognito: no valida su firma, no registra el `sub` del llamante y no puede auditar quién accedió a qué. Un fallo de configuración del gateway, una ruta mal declarada o un endpoint no cubierto por el authorizer se traduce en acceso total sin ninguna barrera posterior.
* **TLS saliente (T6).** Netskope realiza inspección TLS, lo que explica —pero no justifica— la desactivación de la validación de certificados en siete servicios; la solución correcta es confiar en la CA de Netskope, no aceptar cualquier certificado (SEC-004).
* **Gestión de secretos.** La arquitectura provee **AWS Secrets Manager y KMS**, y el despliegue productivo ya inyecta secretos vía `secretKeyRef`. Aun así hay credenciales de proveedores escritas en el árbol de fuentes (SEC-003), lo que contradice el propio diseño.

### 1.3 Principales riesgos

El hallazgo estructural es que **la capa de autenticacion y autorizacion no existe en ninguna de las 11 APIs**. Los contratos OpenAPI declaran `security: - Authorization: []` (Bearer JWT) en los 11 casos, pero:

* `santander.security.enabled: false` con `white-list: /**` en los 11 `application.yml` (ningun perfil `pro`/`pre`/`cert` lo revierte);
* `SecurityConfig.filterChain()` termina en `.anyRequest().permitAll()` en las 10 clases existentes (`beemailboxes` no declara `SecurityConfig`);
* no hay ni un solo `OncePerRequestFilter`, `HandlerInterceptor`, `@PreAuthorize`, `@Secured`, `JwtDecoder` ni `oauth2ResourceServer` en todo el código base.

La consecuencia práctica, dado el diagrama: **el token de Cognito se valida en el borde y se descarta en el backend**. Todo lo que ocurre después de T4 sucede sin identidad. Sobre esa base se apilan operaciones de altísima sensibilidad accesibles con solo cambiar un identificador: posición de tarjetas de cualquier cliente, riesgo crediticio con marcas PEP/PLAFT, consentimientos de datos personales, descarga de documentos contractuales, onboarding biométrico y **generación y validación de OTP**.

A ello se suman:

* **secretos de proveedores versionados** — en v1.5 la mayor parte se ha externalizado a `${SEC_*}` y el refresh token OAuth2 ha desaparecido de `Constant.java`, pero **sobreviven como valor por defecto** en `beclaims/application-local.yml:19-20` (usuario y contraseña de Contáctanos) y `bewatchscreening/application-local.yml:4,6` (`secretKey` y contraseña de Gesintel). Ver SEC-003;
* **validación de certificado TLS deshabilitada** en 6 servicios (`InsecureTrustManagerFactory`); `beemailboxes` la ha corregido (SEC-004);
* el **callback del flujo de firma digital apuntando a `webhook.site`**, un servicio público de terceros —para el que además el diagrama no contempla ninguna ruta de entrada—, con un token de autenticación que por un error de código es la cadena literal `jwt`;
* **fuga en logs**: OTP en claro (tres veces en el mismo flujo), contraseñas de integración, access tokens OAuth2, JWT de callback, **la clave AES de cifrado etiquetada como `method=`** y documentos PDF completos en base64. En v1.6 la fuga de datos biométricos se reduce drásticamente al comprobarse que 26 de los 28 DTO de FacePhi carecen de `@Data`/`@ToString` y sus `log.warn(request)` imprimen la identidad del objeto, no su contenido: queda un único punto real, `FacephiAdapter:130` (ver SEC-012);
* **volcado del inventario documental** (SEC-058, nuevo): `POST /search_documents` acepta el operador `CONTAINS` con cadena vacía sobre cualquier campo y no filtra por titular, devolviendo todos los documentos del sistema junto al DNI de su propietario;
* tres defectos de **gobierno de configuración y de identidad de despliegue**: dos servicios que asumen el rol IAM de otro servicio (SEC-054 — `becustombeprogrm` usa `AWS_IRSA_BEEMAILBOXES` y `bedigitsignature` usa `AWS_IRSA_BEDOCMANAGEMENT`), el despliegue productivo de `becustombeprogrm` leyendo un secreto del almacén de **desarrollo** (SEC-055) y valores de relleno (`xx`, `test`, `12`, `123`) como defecto de variables de entorno en `pre`/`pro` (SEC-056, agravado a High en v1.6).

Se resuelve en este ciclo un hallazgo: **`GET /documents/{id}/versions` ya no ignora el identificador** (SEC-014, ahora `queryByPartitionKey(id)` en lugar de un `Scan` completo).

### 1.4 Conclusión

El perímetro descrito en el diagrama es sólido y reduce de forma significativa la exposición a Internet. El problema es que **toda la seguridad reside en él**: los microservicios operan con confianza implícita total en lo que atraviesa el API Gateway y en lo que llega por la red interna. Esto configura un modelo de "cáscara dura, interior blando" en el que un único fallo perimetral —o cualquier movimiento lateral dentro del VPC— expone íntegramente datos financieros, crediticios, biométricos y de identidad, sin capa de contención ni pista de auditoría atribuible.

Con independencia del perímetro, hay dos clases de riesgo que **ningún control de borde puede mitigar** y que requieren cambios en el código:

1. **BOLA (SEC-002).** Un usuario legítimo de la app móvil, con un token de Cognito perfectamente válido, puede solicitar los datos de cualquier otro cliente cambiando un identificador. Imperva, el WAF, Cognito y el API Gateway lo dejarán pasar porque la petición está correctamente autenticada. Este es el riesgo número uno del conjunto.
2. **Bypass del segundo factor (SEC-005).** La validación de OTP no vincula el código con el usuario, no limita intentos y **descarta el veredicto del proveedor**: se calcula si el OTP es válido y a continuación se ignora el resultado.

Se identificaron **47 hallazgos vivos en alcance**: 6 Critical, 13 High, 19 Medium, 7 Low y 2 Info. Con los 9 aplazados de `becustombeprogrm`, `lmauthorizer` y la recepción de firma digital (§1.1), el total con trazabilidad es de 56. Respecto a la línea base del 31-ago (55 hallazgos), 1 está resuelto, 5 bajan de severidad, 1 empeora y 2 son nuevos. No hay ninguna regresión. Sobre el código se han verificado **ocho acciones de remediación** —dos completas, tres parciales, una inerte y una contraproducente— cuyo inventario está en §20. El detalle de la comparación, en §24.

**Lectura de la tendencia.** El movimiento neto de este ciclo es de mejora, y es visible en el código: `bedocmanagement` incorporó validadores de entrada y corrigió el listado de versiones, `becustombeprogrm` dejó de propagar el cuerpo de error de SKY al consumidor y acotó los reintentos a fallos de red y 5xx, `beidentbiometric` truncó los campos largos antes de persistir su tabla de auditoría, y tres proyectos desactivaron el montaje automático del token de service account.

Pero hay un patrón que se repite por segundo ciclo consecutivo y que es la conclusión operativa más importante de esta versión: **las correcciones se aplican de forma parcial y sin verificación posterior**. Tres ejemplos, todos de esta entrega:

* En `beemailboxes`, `JsonApiClient.validOTP` se reescribió para evaluar de verdad el veredicto de Celmedia (`status == "validated" && isValid()`) — pero el llamante sigue comprobando `status != null`, y como el método ahora devuelve siempre la cadena `"Valid"` o `"Invalid"`, **nunca nula**, la corrección quedó inerte y toda validación de OTP sigue devolviendo `PROCESSED`. El defecto no solo persiste: ahora está enmascarado por código que aparenta corregirlo.
* En `bedocmanagement`, `DocumentMapper.getMapper` dejó de devolver el DNI del titular en el campo `name` — pero `searchMapper`, tres métodos más arriba en el mismo fichero, lo sigue devolviendo.
* En `bedigitsignature` se eliminaron los ficheros `application-pre.yml`, `application-pro.yml`, `application-cert.yml` y `application-local.yml`, dejando un único `application.yml` con valores de relleno (`jwt.secret: ${SEC_SKY_JWT_SECRET:12}`, `role-arn: ${…:test}`) que ahora **aplican también a producción**.

Y **ninguno de los cuatro defectos estructurales se ha tocado**: la autenticación sigue desactivada en los once servicios, no hay autorización de objeto en ninguno, el callback de firma sigue apuntando a `webhook.site` con el token literal `jwt`, y el OTP sigue sin vincularse al usuario.

Prioridades inmediatas:
1. **SEC-002** — implementar autorización a nivel de objeto contra el `sub`/claims del token de Cognito.
2. **SEC-005** — rediseñar el flujo OTP. El primer paso es de una línea: comparar `status` con `"Valid"` en lugar de con `null`.
3. **SEC-058** — filtrar `search_documents` por titular: hoy permite volcar el inventario documental completo, con el DNI de cada titular.
4. **SEC-003** — rotar los secretos expuestos y migrarlos a Secrets Manager (ya disponible en la plataforma).
5. **SEC-001** — validar el JWT de Cognito en el backend, como defensa en profundidad y como base técnica de SEC-002.
6. **SEC-004 / SEC-006** — restaurar la validación TLS confiando en la CA de Netskope, y eliminar el callback a `webhook.site`.

---

## 2. APIs / proyectos analizados

| Proyecto | Ruta base (contrato) | Parent Gluon | Java | Endpoints decl. | Persistencia / Integración | Riesgo |
| -------- | -------------------- | ------------ | ---: | --------------: | -------------------------- | ------ |
| cpe-nxhbsc-beclaims | `/v1/claims_book` | 1.5.2 | 17 | 4 | Contáctanos (GSNET, HTTP claro) | **CRÍTICO** |
| cpe-nxhbsc-becreditrisk | `/v1/credit_risk_decisions` | 1.6.0 | 17 | 1 | RDS Postgres + DynamoDB + Modellica | **CRÍTICO** |
| cpe-nxhbsc-becustombeprogrm | `/v1/customer_benefit_programs` | 1.5.2 | 17 | 5 | DynamoDB + SKY + Qurable | **ALTO** |
| cpe-nxhbsc-bedatacomanagment | `/v7/data_consents_management` | 1.6.0 | 17 | 1 *(era 8)* | DynamoDB | **ALTO** |
| cpe-nxhbsc-bedigitsignature | `/v1` | 1.6.0 | 17 | 1 | DynamoDB + bedocmanagement + FacePhi/Zytrust | **CRÍTICO** |
| cpe-nxhbsc-bedocmanagement | `/v2/document_management` | 1.5.2 | 17 | 9 | S3 + DynamoDB | **CRÍTICO** |
| cpe-nxhbsc-beemailboxes | `/v1/emailboxes` | 1.6.0 | 17 | 3 | DynamoDB + S3 + Celmedia (OTP/mail) | **CRÍTICO** |
| cpe-nxhbsc-beidentbiometric | `/v1/identity_biometric` | 1.6.0 | 17 | 13 | DynamoDB + FacePhi | **CRÍTICO** |
| cpe-nxhbsc-beknowyocustomer | `/v6/know_your_customer` | 1.5.2 | 17 | 3 *(era 20)* | DynamoDB | **ALTO** |
| cpe-nxhbsc-beproducoffering | `/v1/customer_card_position` | 1.5.1 | 17 | 1 | RDS Postgres | **CRÍTICO** |
| cpe-nxhbsc-bewatchscreening | `/v1/watchlist_screening` | 1.6.0 | 17 | 1 | Gesintel / AMLUpdate | **ALTO** |

> **Cambio en v1.6.** El total en alcance queda en **42 operaciones declaradas frente a 37 implementadas**. `bedocmanagement` es el único que se mueve: 9 declaradas (una menos que en v1.5, al desaparecer del contrato la operación `DELETE`) y 6 implementadas. Las cinco operaciones que responden 501 son ahora `PUT /documents/{document_id}`, `POST /documents/{document_id}/consolidate` y `POST /update_document` en `bedocmanagement`; `GET /create` en `beknowyocustomer`; y `GET /health` en `beemailboxes`.
>
> **Cambio en v1.5.** Los contratos se han recortado a lo realmente implementado: el total baja de **67 operaciones declaradas frente a ~26 implementadas** a **43 declaradas frente a 38 implementadas**. `beknowyocustomer` pasa de 20 operaciones a 3 y `bedatacomanagment` de 8 a 1. Quedan cinco operaciones declaradas sin implementar, que responden 501 (SEC-052): `PUT /documents/{document_id}`, `POST /documents/{document_id}/consolidate` y `POST /update_document` en `bedocmanagement`; `GET /create` en `beknowyocustomer`; `GET /health` en `beemailboxes`.
>
> Los servicios "Orquestacion Riesgo Credito" y "Notificaciones Correo" del diagrama se corresponden con `becreditrisk` y `beemailboxes`.
>
> `cpe-nxhbsc-beemailsend` y `cpe-nxhbsc-lmauthorizer` quedan **fuera del alcance** por ser plantillas sin codigo de negocio (ver §1.1 y SEC-057).

---

## 3. Risk Summary

| Severidad | v1.4 (24-ago) | v1.5 (31-ago) | v1.6 (3-sep) | **v1.7 — en alcance** | Aplazados | Total trazable |
| --------- | ------------: | ------------: | -----------: | --------------------: | --------: | -------------: |
| Critical  |             9 |             7 |            7 |                 **6** |         1 |              7 |
| High      |            17 |            18 |           14 |                **13** |         1 |             14 |
| Medium    |            18 |            21 |           25 |                **19** |         6 |             25 |
| Low       |             6 |             6 |            7 |                 **7** |         0 |              7 |
| Info      |             2 |             3 |            3 |                 **2** |         1 |              3 |
| **Total** |        **52** |        **55** |       **56** |                **47** |     **9** |         **56** |

> **v1.7 no es un re-escaneo.** El código no ha cambiado respecto a v1.6: lo único que cambia es el alcance del ejercicio. Los nueve hallazgos aplazados **siguen siendo ciertos y siguen abiertos**; simplemente no se prueban en este Ethical Hacking. La columna «Total trazable» es la que debe usarse para medir la deuda técnica del programa; la de «en alcance», para dimensionar la prueba.

**Movimientos entre v1.5 y v1.6** (detalle completo en §24):

| Clase | N.º | Hallazgos |
| ----- | --: | --------- |
| **RESUELTO** | 1 | SEC-014 |
| **ATENUADO** (baja de severidad) | 5 | SEC-012, SEC-017, SEC-018, SEC-048 (High→Medium); SEC-049 (High→Low) |
| Alcance reducido, misma severidad | 0 | — |
| **AGRAVADO** | 1 | SEC-056 (Medium→High): `bedigitsignature` pierde los perfiles y los valores de relleno alcanzan producción |
| Remediación incompleta (defecto en pie) | 2 | SEC-005 (el veredicto de OTP se calcula y se descarta), SEC-048 (corregido en `getMapper`, no en `searchMapper`) |
| **PERSISTE** sin cambio | 46 | Incluidos los siete Critical: SEC-001, SEC-002, SEC-004, SEC-005, SEC-006, SEC-007, SEC-010 |
| **NUEVO** | 2 | SEC-058, SEC-059 |
| **REGRESIÓN** | 0 | — |

> **La cifra que importa no es el total.** El conjunto pasa de 55 a 56 hallazgos, lo que parece estancamiento; el desglose por severidad cuenta otra historia: los High bajan de 18 a 14 porque cinco hallazgos se han acotado con evidencia (no por criterio más laxo). Lo que no se mueve es el núcleo: **los siete Critical siguen exactamente igual, verificados línea a línea en esta revisión**.

> **Nota sobre las remediaciones incompletas.** Dos correcciones de este ciclo no cambian el comportamiento del sistema pero sí lo hacen más difícil de auditar, porque el código *parece* corregido. Se han clasificado como PERSISTE, no como ATENUADO, y se señalan explícitamente en §24.2: un hallazgo enmascarado es más peligroso que uno visible.

> **Nota sobre `RESUELTO`.** Los dos cierres se han verificado por causa, no por ausencia: `data.sql` no existe en ningún punto del árbol ni queda referencia a él en la configuración (SEC-008), y `CreditRiskMapper:41-42` fija `application` y `channel` como constantes de servidor en lugar de leerlos de las cabeceras (SEC-026). Ninguno de los dos desapareció por salir del alcance.

> **Nota de calibración.** Las severidades incorporan el perímetro del diagrama (Imperva + WAF + Cognito + API Gateway + subred privada). Dos hallazgos se rebajaron respecto a la evaluación basada solo en código: **SEC-009** (Contáctanos viaja por GSNET interno, no por Internet) pasa de Critical a High, y **SEC-025** (Swagger) de Medium a Low al no estar publicado en el gateway. **SEC-002 y SEC-005 no admiten atenuación**: son explotables por un usuario con token válido de Cognito, atravesando todo el perímetro de forma legítima.

---

## 4. Resumen de hallazgos

Los campos **Hallazgo**, **Proyecto** y **Componente** se conservan con la redacción de v1.4 de forma deliberada: son los que alimentan la huella que empareja hallazgos entre auditorías (§21), y reescribirlos produciría un diff falso. Lo que ha cambiado en este ciclo va en la última columna, y el detalle completo, en el bloque de estado de cada hallazgo en §5-§7.

| ID | Severidad | Confianza | Hallazgo | Proyecto | Componente | CWE | Prioridad | Δ v1.6 (3-sep) |
| -- | --------- | --------- | -------- | -------- | ---------- | --- | --------- | --------------- |
| SEC-001 | Critical | CONFIRMADO | Autenticación y autorización desactivadas en todas las APIs | Todos (11) | `SecurityConfig` + `application.yml` | CWE-306 | P0 | — sin cambio |
| SEC-002 | Critical | CONFIRMADO | BOLA/IDOR sistémico sobre identificadores de negocio | 8 proyectos | Delegates / UseCases | CWE-639 | P0 | — sin cambio |
| SEC-003 | High | CONFIRMADO | Secretos de proveedores y BD versionados en el repositorio | 6 proyectos | `application-*.yml`, `Constant.java` | CWE-798 | P1 | **↓ Critical→High.** Externalizados a `${SEC_*}`; quedan 2 perfiles `local` |
| SEC-004 | Critical | CONFIRMADO | Validación de certificado TLS deshabilitada (trust-all) | 7 proyectos | `WebClientConfig` / `RestTemplateConfig` | CWE-295 | P0 | **Alcance 7→6.** `beemailboxes` corregido |
| SEC-005 | Critical | CONFIRMADO | Bypass de OTP: sin vínculo a usuario, sin límite, OTP en path y en logs | beemailboxes | `OTPServiceAdapter` | CWE-304, CWE-307 | P0 | **Remediación incompleta.** `validOTP` ya evalúa el veredicto, pero el llamante sigue comprobando `!= null` |
| SEC-006 | Critical | CONFIRMADO | Callback de firma digital a `webhook.site` y token de callback literal `jwt` | bedigitsignature | `Constant`, `DocumentProcessService` | CWE-200, CWE-306 | P0 | ⏸️ **APLAZADO** — bedigitsignature · recepción. Callback: URL y token del webhook de retorno |
| SEC-007 | Critical | CONFIRMADO | Credenciales, tokens y clave AES escritos en logs | 4 proyectos | `TokenService`, `AesEncryptionService` | CWE-532 | P0 | — sin cambio |
| SEC-009 | Medium | CONFIRMADO | Credenciales enviadas por HTTP en claro a Contáctanos (red interna GSNET) | beclaims | `application-local.yml` + `TokenService` | CWE-319 | P2 | **↓ High→Medium.** `pre`/`pro` sin URL fija |
| SEC-010 | Critical | CONFIRMADO | Fail-open: se devuelven datos ficticios cuando falla el proveedor | beclaims | `ClaimsAdapter` | CWE-754 | P0 | — sin cambio |
| SEC-011 | High | CONFIRMADO | Documento PDF completo en base64 escrito al log | bedigitsignature | `DocumentClient:80` | CWE-532 | P1 | — sin cambio |
| SEC-012 | Medium | CONFIRMADO | Tokens biométricos y datos de DNI escritos al log | beidentbiometric | `FacephiAdapter:130` | CWE-532 | P2 | **↓ High→Medium.** 26 de 28 DTO sin `@ToString`: de 14 puntos de log queda **1** real (`tokenOcr`) |
| SEC-013 | High | CONFIRMADO | `wiretap(true)`: tráfico HTTP completo (incl. `Authorization`) al log | 6 proyectos | `WebClientConfig` | CWE-532 | P1 | — sin cambio |
| SEC-015 | High | ALTA CONFIANZA | Clave S3 y `Content-Type` construidos con datos del cliente sin sanear | bedocmanagement | `DocumentManagementAdapter:115-129` | CWE-99, CWE-434 | P1 | — sin cambio · Tika sigue condicionada a `appId=="biometric"` |
| SEC-016 | Medium | CONFIRMADO | Integraciones salientes sin timeout | 3 proyectos | `WebClientConfig`, `RestTemplateConfig` | CWE-1088 | P2 | ⏸️ **APLAZADO** — becustombeprogrm. Único proyecto que quedaba con el defecto |
| SEC-017 | Medium | CONFIRMADO | Reintentos sobre operaciones no idempotentes sin clave de idempotencia | becustombeprogrm | `SKYServiceAdapter:98` | CWE-837 | P2 | ⏸️ **APLAZADO** — becustombeprogrm. Reintentos sobre el alta en SKY |
| SEC-018 | Medium | CONFIRMADO | Cuerpo de error del proveedor propagado al consumidor | becustombeprogrm, bedigitsignature | `SKYServiceAdapter`, `Util.handleError` | CWE-209 | P2 | **↓ High→Medium.** Cadena (a) **cerrada**: SKY pasa `detail=null` y códigos `TL0015-TL0018`. Cadena (b) intacta en `bedigitsignature` |
| SEC-019 | High | ALTA CONFIANZA | Sin rate limiting: amplificación de recursos y abuso de envío de correo | Todos | — | CWE-770 | P1 | **Parcial.** Rate limiter en `beemailboxes` → genera SEC-053 |
| SEC-020 | High | CONFIRMADO | Payloads base64 sin límite de tamaño ni validación | 4 proyectos | Contratos OpenAPI + adapters | CWE-400 | P1 | — sin cambio |
| SEC-021 | High | CONFIRMADO | Endpoint `download_document_intern` público y confianza transitiva | bedocmanagement ← bedigitsignature | `openapi.yaml`, `WebClientConfig` | CWE-668 | P1 | — sin cambio · agravado por SEC-054 |
| SEC-022 | High | CONFIRMADO | Actuator expuesto sin autenticación con `show-details: ALWAYS` | Todos | `application.yml` + `SecurityConfig` | CWE-200 | P1 | — sin cambio (12/12) |
| SEC-023 | Medium | CONFIRMADO | JWT M2M sin `iss`/`aud`/`jti`, clave AES reutilizada como clave JWT, expiración de 20 s | becustombeprogrm, bedigitsignature | `JwtUtil`, `SkyTokenService` | CWE-1270, CWE-613 | P2 | ⏸️ **APLAZADO** — becustombeprogrm + bedigitsignature · recepción. `JwtUtil` solo emite el token del callback |
| SEC-024 | Medium | CONFIRMADO | AES sin cifrado autenticado y transformación tomada de configuración | becustombeprogrm | `AesEncryptionService:30-46` | CWE-353 | P2 | ⏸️ **APLAZADO** — becustombeprogrm. Cifrado del payload hacia SKY |
| SEC-025 | Low | CONFIRMADO | Swagger UI y `/v3/api-docs` habilitados en todos los perfiles (no publicados en el gateway) | Todos | `application.yml`, `SecurityConfig` | CWE-200 | P3 | — sin cambio |
| SEC-027 | Medium | REQUIERE VALIDACIÓN | `forward-headers-strategy: framework` sin proxy de confianza verificado | Todos | `application.yml` | CWE-348 | P2 | — sin cambio (12/12) |
| SEC-028 | Medium | CONFIRMADO | Excepciones no mapeadas producen 500 con posible detalle interno | 5 proyectos | Varios | CWE-248 | P2 | — sin cambio · ningún `@ExceptionHandler(Exception.class)` |
| SEC-029 | Medium | CONFIRMADO | `ddl-auto: update` y `sql.init.mode: always` en producción | beproducoffering | `application-pro.yml` | CWE-16 | P2 | — sin cambio |
| SEC-030 | Medium | CONFIRMADO | `patchConsent` usa `putIfAbsent`: la actualización nunca se aplica | bedatacomanagment | `DataConsentManagementAdapter:79-96` | CWE-670 | P2 | **Remediación incompleta.** Ahora todo `PATCH` válido devuelve 500 |
| SEC-031 | Medium | CONFIRMADO | JWT almacenado como partition key en DynamoDB | bedigitsignature | `Entity.java:29-33` | CWE-522 | P2 | ⏸️ **APLAZADO** — bedigitsignature · recepción. El JWT se guarda para casar el callback entrante |
| SEC-032 | Medium | CONFIRMADO | Backdoor de pruebas `CONTRATO_CLIENTE` devuelve un PDF del classpath | bedigitsignature | `DocumentClient:37-46` | CWE-489 | P2 | — sin cambio |
| SEC-033 | Medium | CONFIRMADO | Token cacheado sin expiración ni renovación | beclaims | `TokenService:38-43` | CWE-613 | P2 | — sin cambio |
| SEC-034 | Medium | CONFIRMADO | Deriva de versiones; `bedatacomanagment` mezcla Netty 4.1.x y 4.2.x | Todos | `pom.xml` | CWE-1104 | P2 | **Corregido en `beclaims`** (las entradas 4.2.x están comentadas). `bedatacomanagment` mezcla ahora **tres** líneas: 4.1.135, 4.2.13 y 4.2.16 |
| SEC-035 | Medium | CONFIRMADO | `assert` usado para control de flujo (inactivo en runtime) | beemailboxes | `JsonTokenProvider:56`, `XmlTokenProvider:51` | CWE-617 | P2 | — sin cambio |
| SEC-036 | Medium | REQUIERE VALIDACIÓN | `XmlMapper` sin endurecimiento explícito frente a DTD/entidades externas | beemailboxes | `XmlApiClient:31` | CWE-611 | P2 | — sin cambio |
| SEC-037 | Medium | CONFIRMADO | Sin idempotencia ni anti-replay en operaciones sensibles | bedigitsignature, becustombeprogrm, beemailboxes | — | CWE-799 | P2 | — sin cambio |
| SEC-038 | Medium | REQUIERE VALIDACIÓN | Datos externos escritos al log sin neutralizar (log injection) | 6 proyectos | Varios | CWE-117 | P2 | — sin cambio |
| SEC-039 | Medium | CONFIRMADO | `search_documents` ejecuta Scan completo de DynamoDB sin paginación | bedocmanagement | `BaseDynamoRepository:76-92` | CWE-405 | P2 | — sin cambio · explotado por SEC-058 |
| SEC-040 | Medium | ALTA CONFIANZA | `validate_status` devuelve siempre `"Match Found"` | bewatchscreening | `GesintelAdapter:100-115` | CWE-393 | P2 | — sin cambio |
| SEC-041 | Low | CONFIRMADO | Generador de códigos con PRNG no criptográfico y espacio reducido (código muerto) | beemailboxes | `UtilsOtp:22-36` | CWE-338 | P3 | — sin cambio |
| SEC-042 | Low | CONFIRMADO | Endpoints internos y hostnames de BD revelados en el repositorio | 3 proyectos | `application-local.yml`, test properties | CWE-200 | P3 | — sin cambio |
| SEC-043 | Low | CONFIRMADO | `automountServiceAccountToken: true` en despliegue productivo | Todos | `.gluon/cd/pro/values-pro.yaml` | CWE-250 | P3 | — **sin cambios respecto a v1.5.** Siguen en `true` los mismos 4 (beclaims, bedocmanagement, beemailboxes, beknowyocustomer); 3 en `false` y 5 sin declararlo |
| SEC-044 | Low | CONFIRMADO | CSP definida para API JSON; falta política de cabeceras adecuada al tipo de servicio | Todos | `SecurityConfig` | CWE-1021 | P3 | — sin cambio |
| SEC-045 | Info | CONFIRMADO | `jwks.json` con claves públicas presente pero no utilizado | beclaims | `src/main/resources/jwks.json` | — | P3 | — sin cambio |
| SEC-046 | Info | CONFIRMADO | 67 operaciones declaradas frente a ~26 implementadas | Todos | Contratos OpenAPI | — | P3 | **42 declaradas en alcance / 37 implementadas.** `bedocmanagement` añade 3 operaciones no implementadas |
| SEC-047 | High | CONFIRMADO | Enumeración diferencial: tres respuestas distintas ante recurso inexistente | bedocmanagement | `DocumentManagementAdapter:60-71,177-185,199-216` | CWE-204 | P1 | — sin cambio |
| SEC-048 | Medium | CONFIRMADO | El DNI del titular se devuelve en el campo `name` de los metadatos | bedocmanagement | `DocumentMapper:44-55` | CWE-359 | P2 | **↓ High→Medium · remediación incompleta.** Corregido en `getMapper`; `searchMapper:49` sigue devolviendo el DNI |
| SEC-049 | Low | CONFIRMADO | `deleteDocument` sin verificación de titularidad ni de existencia | bedocmanagement | `DocumentManagementAdapter:200-217` | CWE-639 | P3 | **↓ High→Low.** Ya comprueba existencia y **no es alcanzable**: `removeDocument` no implementa ningún delegate y el contrato no declara `DELETE` |
| SEC-050 | Medium | CONFIRMADO | El path variable determina el verbo HTTP hacia el proveedor | becustombeprogrm | `QurableServiceAdapter:80-92,169-178` | CWE-470 | P2 | ⏸️ **APLAZADO** — becustombeprogrm. Verbo HTTP hacia Qurable |
| SEC-051 | Medium | CONFIRMADO | Campos cruzados en `FileEntity`: `customerId` guarda el id del documento | bedocmanagement | `FileEntity:18-36`, `DocumentMapper:71-90` | CWE-1109 | P2 | **Alcance 1→3.** El mismo patrón en `beemailboxes` (`OtpEntity:19-35`, el OTP es la PK) y `bedigitsignature` (`Entity:113-134`, el JWT se guarda en `documentNumber`) |
| SEC-052 | Low | CONFIRMADO | Endpoints declarados que responden 501 Not Implemented | beknowyocustomer, bedatacomanagment | Contratos + delegates | CWE-1059 | P3 | — sin cambio (5): bedocmanagement (3), beknowyocustomer (1), beemailboxes (1) |
| SEC-053 | High | CONFIRMADO | La limitación de OTP cubre la generación pero no la validación y el registro crece sin cota | beemailboxes | `EmailboxIdInputPort:39-70`, `RateLimiterConfig:12-22` | CWE-307, CWE-770 | P1 | — sin cambio · el registro de `RateLimiter` sigue sin cota |
| SEC-054 | High | CONFIRMADO | Dos servicios asumen el rol IAM de otro servicio | becustombeprogrm, bedigitsignature | `application-*.yml` role-arn | CWE-269, CWE-1268 | P1 | — sin cambio · ahora en `bedigitsignature/application.yml:63`, que aplica a **todos** los entornos |
| SEC-055 | High | CONFIRMADO | El despliegue productivo lee un secreto del almacén de desarrollo | becustombeprogrm | `.gluon/cd/pro/values-pro.yaml:37-42` | CWE-1188, CWE-798 | P1 | ⏸️ **APLAZADO** — becustombeprogrm. Secreto de Qurable en el chart de `pro` |
| SEC-056 | High | CONFIRMADO | Valores de relleno como defecto de variables de entorno en perfiles pre y pro | 4 proyectos | `application-pro.yml`, `application.yml` | CWE-453, CWE-1188 | P1 | **↑ Medium→High.** `bedigitsignature` elimina los cuatro perfiles: `jwt.secret:12` y `role-arn:test` aplican también a producción |
| SEC-057 | Info | CONFIRMADO | El proyecto del Lambda Authorizer existe pero está vacío | lmauthorizer | `src/helloworld.js`, `deployment.yml` | — | P1 | ⏸️ **APLAZADO** — lmauthorizer. Proyecto completo fuera de alcance |
| SEC-058 | High | CONFIRMADO | `search_documents` permite volcar el inventario documental completo con el DNI del titular | bedocmanagement | `DocumentManagementAdapter:80-97`, `FileSearchMapper:15-49`, `ExpressionBuilder:42-67` | CWE-639, CWE-200 | P1 | **NUEVO** |
| SEC-059 | Medium | CONFIRMADO | La tabla de auditoría biométrica guarda DNI y tokens de sesión en claro, sin TTL | beidentbiometric | `BiometricInputPort:369-415`, `LogApiBiometric:73-91` | CWE-312, CWE-359 | P2 | **NUEVO** |

---

> **Hallazgos aplazados.** Las nueve filas marcadas ⏸️ siguen en la tabla a propósito: el defecto existe y el código sigue desplegado. No cuentan para el alcance del Ethical Hacking (47 hallazgos) pero sí para la deuda técnica del programa (56). Ver §1.1 y §20.

> **Hallazgos cerrados en este ciclo:** SEC-008 y SEC-026 salen de esta tabla porque ya no describen el estado del código. Se conservan con su identificador y su verificación en §20.

---

## 5. Detalle de hallazgos

### SEC-001 — Autenticación y autorización completamente desactivadas en las 11 APIs

**Severidad:** Critical · **Confianza:** CONFIRMADO · **Prioridad:** P0
**CWE:** CWE-306 (Missing Authentication for Critical Function), CWE-1188 (Insecure Default Initialization)
**OWASP API Security Top 10:** API2:2023 Broken Authentication · API8:2023 Security Misconfiguration
**Proyecto/API:** los 11

#### Ubicación

```text
Archivo: <cada-proyecto>/src/main/resources/config/application.yml
Bloque:  santander.security
Lineas:  22-25 (beclaims), equivalente en los 11 proyectos

Archivo: <cada-proyecto>/src/main/java/.../infrastructure/config/SecurityConfig.java
Clase:   SecurityConfig
Metodo:  filterChain(HttpSecurity)
Lineas:  31-42 (beclaims); 25-33 (becustombeprogrm); equivalentes en las 10 clases existentes
```

#### Descripción

Existen dos capas de seguridad y **ambas están anuladas**:

1. **Framework corporativo.** El starter `santander-spring-boot-starter-authentication` está declarado como dependencia en los `pom.xml`, pero la configuración lo desactiva:

```yaml
santander:
  security:
    enabled: false
    white-list:
      - /**
```

Ningun `application-pro.yml`, `application-pre.yml` ni `application-cert.yml` sobrescribe estos valores: se verificaron los 11 proyectos, en los tres perfiles.

2. **Spring Security propio.** La cadena de filtros deja pasar todo:

```java
// SecurityConfig.java  (beclaims 31-42, idéntico en 9 proyectos más)
http.securityMatcher("/**")
    .authorizeHttpRequests(
        auth -> auth.requestMatchers(HttpMethod.GET, "/v3/api-docs/**").permitAll()
                    .requestMatchers(HttpMethod.GET, "/swagger-ui/**").permitAll()
                    .requestMatchers(HttpMethod.GET, "/actuator/**").permitAll()
                    .anyRequest()
                    .permitAll())          // <-- todo el resto también
    .csrf(AbstractHttpConfigurer::disable)
    ...
```

`cpe-nxhbsc-beemailboxes` ni siquiera tiene `SecurityConfig`.

Todo esto **contradice el contrato publicado**. Los 12 `openapi.yaml` declaran:

```yaml
security:
  - Authorization: []
components:
  securitySchemes:
    Authorization:
      type: http
      scheme: bearer
      bearerFormat: JWT
```

y documentan explícitamente el código de error `TL0001 | 401 | No se cuenta con credenciales válidas para acceder al recurso.` — un 401 que el código nunca puede producir.

Confirmacion adicional: la **plantilla corporativa de partida trae la autenticacion activada**. El proyecto `cpe-nxhbsc-beemailsend` (fuera del alcance de esta revision por ser una plantilla sin codigo de negocio) conserva el `application.yml` original, y en el si esta declarado el conector de autenticacion:

```yaml
santander:
  security:
    connectors:
      pkm-connector:
        pkm-endpoint:
          - ${env.pkm-endpoint}
```

Es decir, el estado por defecto de la plantilla corporativa incluye autenticación; los otros once proyectos la retiraron de forma deliberada.

Búsquedas exhaustivas sobre `*/src/main` que no devuelven **ningún** resultado: `OncePerRequestFilter`, `GenericFilterBean`, `HandlerInterceptor`, `FilterRegistrationBean`, `@PreAuthorize`, `@Secured`, `@RolesAllowed`, `@EnableMethodSecurity`, `JwtDecoder`, `oauth2ResourceServer`.

#### Flujo

```text
Cualquier cliente HTTP
   ↓  (sin Authorization)
SecurityFilterChain → anyRequest().permitAll()
   ↓
ApiDelegateImpl (sin comprobación de principal)
   ↓
UseCase → Adapter
   ↓
DynamoDB / S3 / RDS / proveedor externo
```

#### Source

Petición HTTP arbitraria a cualquier ruta del servicio. No se requiere credencial alguna.

#### Sink

Todas las operaciones de negocio: consulta de posición de tarjetas, decisión de riesgo crediticio, consentimientos de datos personales, descarga y borrado de documentos, onboarding biométrico, generación y validación de OTP, envío de correo, firma de documentos.

#### Escenario de explotación

El diagrama de arquitectura sitúa los pods en una subred privada, tras `AWS PrivateLink` → `API Gateway` → `AWS WAF` → `Imperva` → `Akamai`, con `Amazon Cognito` como autorizador. **Esto elimina el escenario de acceso directo desde Internet**, y por eso este hallazgo no se evalúa como "API pública sin autenticación". El riesgo real es otro, y persiste:

1. **Tráfico este-oeste (frontera T5).** Los once servicios comparten la misma subred privada del VPC. Cualquier pod comprometido —o cualquier workload con ruta al NLB o a los `Service` de Kubernetes— invoca a los demás **sin atravesar Akamai, Imperva, el WAF, Cognito ni el API Gateway**. En ese plano no existe ningún control: ni autenticación, ni autorización, ni registro atribuible. La superficie lateral incluye biometría, documentos, riesgo crediticio y OTP.
2. **Ausencia de defensa en profundidad (frontera T4).** El backend descarta el JWT de Cognito. Cualquier desviación del perímetro —una ruta añadida al API Gateway sin authorizer, un endpoint no cubierto por el mapeo, un cambio de configuración, un fallo del autorizador que devuelva *allow* por defecto— se traduce en acceso completo sin ninguna barrera posterior. Un unico punto de fallo protege once servicios.
3. **Imposibilidad de autorizar y de auditar.** Al no leer el token, el servicio no conoce el `sub`, el `client_id` ni los `scope` del llamante. Esto hace **técnicamente imposible** implementar autorización a nivel de objeto (SEC-002) y deja los registros sin atribución: ante un incidente no puede reconstruirse quién accedió a qué.
4. **`beemailboxes` ni siquiera declara `SecurityConfig`**, por lo que depende exclusivamente de la configuracion del framework, tambien desactivada.

#### Impacto

* **Confidencialidad:** en el plano este-oeste, acceso sin restricción a datos financieros, crediticios, biométricos y de identidad de cualquier cliente.
* **Integridad:** creación y modificación de consentimientos, borrado de documentos, alta de usuarios y disparo de firmas sin identidad asociada.
* **Trazabilidad:** ausencia total de atribucion en los registros de las once APIs — relevante para investigación forense y para los requisitos de auditoría de la SBS.
* **Arquitectura:** modelo de confianza "cáscara dura, interior blando", contrario al principio de confianza cero y a los requisitos de autenticación de APIs del propio grupo.

Este hallazgo es el **habilitador técnico** de SEC-002 (sin token leído no hay autorización posible) y agrava SEC-005, SEC-014, SEC-021 y SEC-022. Su corrección es requisito previo para SEC-002.

#### Remediación

1. Reactivar el control del framework en **todos** los perfiles y reducir la whitelist a lo estrictamente necesario:

```yaml
santander:
  security:
    enabled: true
    white-list:
      - /actuator/health/**
```

2. Sustituir el `permitAll` global por una cadena que exija autenticación por defecto, **validando el mismo JWT que ya emite Amazon Cognito** en el borde. El backend no necesita un nuevo mecanismo: le basta con dejar de descartar el token que ya viaja en la petición:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/**")
        .authorizeHttpRequests(auth -> auth
            .requestMatchers(HttpMethod.GET, "/actuator/health/**").permitAll()
            .requestMatchers("/actuator/**").hasAuthority("SCOPE_ops.monitor")
            .requestMatchers("/v3/api-docs/**", "/swagger-ui/**").denyAll() // ver SEC-025
            .anyRequest().authenticated())                                   // <-- por defecto denegar
        .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt
            .jwtAuthenticationConverter(scopeConverter())))
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .csrf(AbstractHttpConfigurer::disable)   // correcto para API stateless sin cookies
        .headers(h -> h
            .contentTypeOptions(Customizer.withDefaults())
            .httpStrictTransportSecurity(Customizer.withDefaults())
            .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny));
    return http.build();
  }
}
```

3. Configurar el `JwtDecoder` contra el **JWKS del User Pool de Cognito**, validando issuer, audience y expiración (ver SEC-023):

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          # https://cognito-idp.{region}.amazonaws.com/{userPoolId}
          issuer-uri: ${COGNITO_ISSUER_URI}
          audiences: ${COGNITO_APP_CLIENT_ID}
```

Nota: `beclaims` ya incluye un `src/main/resources/jwks.json` con dos claves RSA públicas y `kid` en formato Cognito (SEC-045), pero **no se referencia desde ningún punto del código**. Debe sustituirse por la resolución dinámica del JWKS vía `issuer-uri`, que gestiona la rotación de claves automáticamente; fijar el JWKS en un fichero provocaría una caída del servicio en la siguiente rotación.

4. **Aplicar autenticación también en el plano este-oeste.** El JWT de Cognito cubre las llamadas que entran por el API Gateway, pero no las llamadas pod-a-pod (`bedigitsignature` → `bedocmanagement`, SEC-021). Para ese tramo, elegir una de estas opciones y aplicarla de forma consistente:
   * **mTLS de malla** (service mesh) con identidad de workload — preferible, transparente al código;
   * o **token de cliente propio** obtenido por client-credentials contra Cognito, con un `scope` distinto al de los consumidores externos (por ejemplo `document.read.internal`), validado en `bedocmanagement`.
   Adicionalmente, aplicar `NetworkPolicy` de Kubernetes para que solo los pods autorizados puedan alcanzar cada servicio.

5. Añadir un test de integración que falle si algún endpoint de negocio responde distinto de 401 sin `Authorization`. Los `SecurityConfigTest` actuales solo verifican con mocks que `permitAll()` fue invocado — es decir, **blindan el comportamiento inseguro** y darían por bueno cualquier regresión.

#### Nota sobre el entorno de desarrollo: por qué la configuración actual no logra lo que pretende

El equipo ha indicado que **en desarrollo no se utiliza Cognito**, y que esa es la razón por la que se desactivó la seguridad. Es una motivación legítima y muy común. El problema es que **la desactivación no quedó acotada a desarrollo**: por la forma en que está implementada, se aplica en los cuatro entornos.

Hay dos mecanismos distintos y ambos son globales:

**1. `application.yml` es el fichero base, no el de desarrollo.**

```text
src/main/resources/config/
├── application.yml          ← santander.security.enabled: false  · SE APLICA A TODOS LOS PERFILES
├── application-local.yml
├── application-cert.yml
├── application-pre.yml
└── application-pro.yml
```

En Spring Boot, `application.yml` sin sufijo define la configuración común y los ficheros `application-<perfil>.yml` la **sobrescriben** cuando ese perfil está activo. Como ninguno de los perfiles `cert`, `pre` ni `pro` redefine `santander.security`, el valor `false` del fichero base es el que rige también en producción. Se verificó fichero por fichero en los 11 proyectos.

**2. `SecurityConfig.java` no es configurable por perfil en absoluto.**

```java
// SecurityConfig.java — se compila y se aplica en TODOS los entornos, sin excepción
.anyRequest().permitAll()
```

Aunque se corrigiera el punto 1, esta línea seguiría abriendo todos los endpoints en producción. Es código Java, no configuración: no hay perfil, variable de entorno ni parámetro de despliegue que lo desactive.

Dicho de otro modo: la intención era *"que en local no haga falta un token"*, y el resultado es *"que en ningún entorno haga falta un token"*.

#### Remediación recomendada: invertir el valor por defecto

El principio es que **la configuración segura sea la que se hereda, y la relajación sea una excepción explícita, nombrada y acotada a un perfil que nunca se despliega**.

**Paso 1 — Mover la desactivación al perfil `local` únicamente.**

```yaml
# application.yml (base) — RECOMENDADO: seguro por defecto
santander:
  security:
    enabled: true
    white-list:
      - /actuator/health/**
```

```yaml
# application-local.yml — la relajación vive aquí y solo aquí
santander:
  security:
    enabled: false
    white-list:
      - /**
```

Con esto, un despliegue con el perfil equivocado o sin perfil arranca **seguro**, no abierto. Es el comportamiento deseable: el fallo de configuración debe cerrar, no abrir.

**Paso 2 — Condicionar `SecurityConfig` por perfil.**

```java
// Código recomendado — dos beans mutuamente excluyentes, explícitos en su intención
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /** Cadena real: aplica en cert, pre y pro. */
    @Bean
    @Profile("!local")
    public SecurityFilterChain secureFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/actuator/health/liveness",
                                                 "/actuator/health/readiness").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable)
            .headers(h -> h
                .contentTypeOptions(Customizer.withDefaults())
                .httpStrictTransportSecurity(Customizer.withDefaults())
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny));
        return http.build();
    }

    /** Cadena de desarrollo local. Nunca se activa en un entorno desplegado. */
    @Bean
    @Profile("local")
    public SecurityFilterChain localFilterChain(HttpSecurity http) throws Exception {
        log.warn("=== PERFIL LOCAL: autenticacion DESACTIVADA. No usar fuera de desarrollo. ===");
        http.securityMatcher("/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
```

El log de advertencia en el arranque es deliberado: si alguna vez aparece en el arranque de un pod de `cert`, `pre` o `pro`, el error se detecta de inmediato en lugar de pasar inadvertido durante meses.

**Paso 3 — Elegir cómo desarrollar sin Cognito.** Tres opciones, de mejor a peor:

| Opción | Cómo funciona | Ventaja | Inconveniente |
| ------ | ------------- | ------- | ------------- |
| **A. Emisor local (recomendada)** | Keycloak o Spring Authorization Server en `docker-compose`; en `application-local.yml` se apunta `issuer-uri` a `http://localhost:8080/realms/dev` | **Mismo camino de código en todos los entornos.** Hay principal, hay claims, la autorización de objeto (SEC-002) se ejercita en local | Requiere un contenedor más en el entorno de desarrollo |
| **B. `JwtDecoder` de desarrollo** | Bean `@Profile("local")` que valida con una clave simétrica local; el desarrollador genera tokens con un script | Sin infraestructura adicional | Hay que mantener el generador de tokens |
| **C. `permitAll` en local** | La cadena permisiva del paso 2 | Cero fricción | **No hay principal.** El código de autorización de SEC-002 no se ejercita y puede fallar con `NullPointerException` en cuanto se despliega |

La **opción A es claramente preferible**, y la razón es concreta: en cuanto se implemente la autorización de objeto (SEC-002), el código hará `SecurityContextHolder.getContext().getAuthentication().getPrincipal()`. Con la opción C ese principal es `anonymousUser` o `null` en local, de modo que **la ruta de código más importante para la seguridad sería la única que nunca se prueba antes de producción**. Con la opción A se prueba en cada ejecución local.

```yaml
# application-local.yml — opción A
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8080/realms/nexhub-dev

santander:
  security:
    enabled: false      # el conector PKM corporativo sigue sin usarse en local...
```

```yaml
# application-pro.yml — mismo código, distinto emisor
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${COGNITO_ISSUER_URI}
          audiences: ${COGNITO_APP_CLIENT_ID}
```

La diferencia entre local y producción queda reducida a **una URL en un fichero de configuración**. Ese es el objetivo: que el entorno cambie, no el código.

**Paso 4 — Guardarraíles que impidan la regresión.** Sin ellos, la configuración volverá a derivar:

```yaml
# .github/workflows/security.yml — job adicional recomendado
- name: Verificar que la seguridad no esta desactivada fuera de local
  run: |
    if grep -rn "enabled: false" src/main/resources/config/          --include="application.yml"          --include="application-cert.yml"          --include="application-pre.yml"          --include="application-pro.yml" | grep -q "security"; then
      echo "ERROR: santander.security.enabled=false fuera de application-local.yml"
      exit 1
    fi
    if grep -rn "anyRequest()" src/main/java --include="*.java" | grep -q "permitAll"; then
      if ! grep -rn -B5 "anyRequest().permitAll()" src/main/java --include="*.java" | grep -q '@Profile("local")'; then
        echo "ERROR: anyRequest().permitAll() sin @Profile(\"local\")"
        exit 1
      fi
    fi
```

Y un test de integración que se ejecute con el perfil `test` (no `local`), de forma que verifique la cadena real:

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class SecurityIntegrationTest {

    @Autowired private TestRestTemplate rest;

    @Test
    void debeRechazarPeticionSinToken() {
        ResponseEntity<String> res = rest.getForEntity("/v1/customer_card_position/list?customer_id=1234567890",
                                                       String.class);
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);   // no 200
    }

    @Test
    void debeRechazarTokenDeOtroCliente() {                                   // cubre SEC-002
        HttpHeaders h = new HttpHeaders();
        h.setBearerAuth(tokenParaCliente("1111111111"));
        ResponseEntity<String> res = rest.exchange("/v1/customer_card_position/list?customer_id=2222222222",
                                                   HttpMethod.GET, new HttpEntity<>(h), String.class);
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
}
```

Este segundo test es el que hoy no existe y el que habría detectado tanto SEC-001 como SEC-002. Los `SecurityConfigTest` actuales, en cambio, verifican con mocks que `permitAll()` **fue invocado**: no comprueban seguridad, comprueban que la inseguridad sigue en su sitio.

**Punto que conviene no perder de vista.** Activar Cognito en el backend cierra SEC-001, pero **no cierra SEC-002**. Un token válido de un cliente seguirá sirviendo para consultar los datos de otro mientras no se compare el identificador solicitado con el sujeto del token. Los dos cambios son necesarios, y el orden natural es SEC-001 primero (habilita técnicamente al segundo) y SEC-002 inmediatamente después.


---

### SEC-002 — BOLA / IDOR sistémico: identificadores de negocio sin control de autorización

**Severidad:** Critical · **Confianza:** CONFIRMADO · **Prioridad:** P0
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-284
**OWASP API Security Top 10:** API1:2023 Broken Object Level Authorization
**Proyecto/API:** beproducoffering, becreditrisk, bedatacomanagment, bedocmanagement, beknowyocustomer, becustombeprogrm, beemailboxes, bedigitsignature

#### Ubicación

```text
beproducoffering  · HelloApiDelegateImpl.java:64-72        · getCardPosition(..., customerId, ...)
becreditrisk      · CreditRiskManagementInputPort.java:46-77 · validateCreditRisk(criteria)
bedatacomanagment · DataConsentManagementAdapter.java:37-93 · getConsent / postConsent / patchConsent
bedocmanagement   · DocumentManagementAdapter.java:61-71,178-185,200-215 · downloadDocument / getDocument / deleteDocument
beknowyocustomer  · KnowYourCustomerUseCaseImpl.java:36-57 · getRiskScore(criteria)
becustombeprogrm  · QurableServiceAdapter.java:133-167,190-224 · getUser / getUsersQurable
bedigitsignature  · DocumentProcessService.java:75-80      · retrieveDocument(documentId)
```

#### Descripción

Cada una de estas operaciones recibe del consumidor un identificador que designa el objeto de negocio y lo utiliza directamente contra la persistencia o el proveedor, **sin ninguna comprobación de que el solicitante tenga derecho sobre ese objeto**. Al no existir principal autenticado (SEC-001), no hay nada contra lo que comparar.

El caso más directo es `beproducoffering`:

```java
// HelloApiDelegateImpl.java:64-72
@Override
public ResponseEntity<WrapperCustomerPositionResponse> getCardPosition(List<String> typeCode,
                                                                       Boolean groupByTypeCode,
                                                                       String filteringStatusCode,
                                                                       String customerId,
                                                                       String fields) {
    log.info("Log from Servlet controller");
    return ResponseEntity.ok(channelServiceInputPort.getServices(customerId));
}
```

El único control existente es de **formato**, no de propiedad:

```java
// CustomerIdValidator.java:14-23
private static final Pattern CUSTOMER_ID_PATTERN = Pattern.compile("^\\d{10}$");
```

Un patrón de 10 dígitos no restringe el acceso: define un espacio enumerable.

En `becreditrisk` el objeto es aún más sensible — el `documentNumber` del request se usa para recuperar el expediente crediticio completo y enviarlo al motor de decisión:

```java
// CreditRiskManagementInputPort.java:48-64
DocumentIdRecord documentId = creditRiskValidateCriteria.getCustomerAccountHolder().getId();
Person personRecord = creditRiskManagementOutputPort.findPersonRecordByDocumentId(documentId);
CustomerCloudRecord customerCloudRecord = ...findCustomerCloudRecordByDocumentId(documentId);
CustomerScp customerScpRecord = ...findCustomerScpRecordByDocumentId(documentId);
List<Cma> cmaRecord = ...findCmaRecordByDocumentId(documentId);
```

El contenido de `CMA` incluye clasificaciones como `UPLA - PEP`, `UPLA - PLAFT` y `Castigo, Deficiente o Peor en los últimos 48 meses` (ver `data.sql`, SEC-008).

En `bedatacomanagment` el `partyId` gobierna lectura **y escritura** de consentimientos de tratamiento de datos personales — el registro que legitima el uso de los datos del cliente:

```java
// DataConsentManagementAdapter.java:37-93
public WrapperGetConsentsOutput getConsent(String partyId) { ... consentRepository.getByKey(partyId) ... }
public List<WrapperConsentId> postConsent(List<...> criteria, String partyId) { ... }
public Void patchConsent(WrapperPatchConsentRequestBody criteria, String partyId, String consentId) { ... }
```

#### Flujo

```text
POST /v1/credit_risk_decisions/decide_risk   {"customerAccountHolder":{"id":{"documentNumber":"<DNI ajeno>"}}}
   ↓
CreditRiskDelegateImpl.validateCreditRisk()      ← sin principal
   ↓
CreditRiskManagementInputPort.validateCreditRisk()  ← sin comprobación de propiedad
   ↓
RDS Postgres (CREDIT_RISK, person, customer_cloud, customer_scp) + Modelica
   ↓
Respuesta 200 con el perfil de riesgo del titular ajeno
```

#### Source

`customer_id` (query param), `documentNumber` / `dni` (body), `party_id`, `document_id`, `consent_id`, `questionnaire_id`, `key`, `emailbox_id` (path/body).

#### Sink

Consultas a DynamoDB / RDS / S3 y llamadas a proveedores que devuelven el objeto completo al solicitante.

#### Escenario de explotación

**Este es el hallazgo que el perímetro no puede mitigar, y por ello el de mayor riesgo real del conjunto.**

Un usuario legítimo de la app móvil se autentica normalmente contra Amazon Cognito y obtiene un token válido. Con ese token —que Akamai, Imperva, el AWS WAF, Cognito y el API Gateway aceptarán sin objeción, porque es correcto— envía la petición cambiando únicamente el identificador del objeto:

```text
GET /v1/customer_card_position/list?customer_id=<otro cliente>
Authorization: Bearer <token de Cognito válido, del atacante>
```

Ningún control del borde puede detectarlo: la autenticación es correcta, la ruta es correcta, el esquema del parámetro es correcto. La única capa capaz de decidir que ese `customer_id` no le corresponde al portador del token es el microservicio, **y el microservicio no lee el token** (SEC-001).

A partir de ahí, iterar el identificador. Con `customer_id` de 10 dígitos o con el DNI peruano (8 dígitos), el espacio es enumerable, y las cuotas del API Gateway/Imperva limitan el ritmo pero no impiden la extracción sostenida. El resultado es la obtención del padrón de clientes con su posición de productos y su clasificación de riesgo, sin que quede en los registros del backend ninguna traza de qué identidad realizó cada consulta.

#### Impacto

* **Confidencialidad:** extracción masiva de datos personales y financieros.
* **Integridad:** en `bedatacomanagment` y `bedocmanagement`, alteración y borrado de registros de terceros.
* **Negocio:** el consentimiento de tratamiento de datos es prueba legal; su manipulación por terceros compromete la defensa del banco ante la autoridad de protección de datos.

#### Remediación

La autorización debe derivar del **principal autenticado**, nunca del parámetro.

```java
// Código vulnerable
public ResponseEntity<WrapperCustomerPositionResponse> getCardPosition(..., String customerId, ...) {
    return ResponseEntity.ok(channelServiceInputPort.getServices(customerId));
}

// Código recomendado
public ResponseEntity<WrapperCustomerPositionResponse> getCardPosition(..., String customerId, ...) {
    Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    authorizationService.assertCanAccessCustomer(jwt, customerId);   // 403 si no procede
    return ResponseEntity.ok(channelServiceInputPort.getServices(customerId));
}
```

Con el patrón recomendado para integraciones M2M:

* **Consumidor delegado (actúa por un cliente concreto):** el `customer_id` no viaja como parámetro, se deriva del claim `sub` del token del usuario final propagado, o se valida contra él.
* **Consumidor de sistema (batch, back-office):** exigir un `scope` específico (`credit_risk.read.all`) y registrar auditoría con `client_id` + objeto accedido en cada acceso.

```java
@Component
@RequiredArgsConstructor
public class CustomerAuthorizationService {

  public void assertCanAccessCustomer(Jwt jwt, String customerId) {
    List<String> scopes = jwt.getClaimAsStringList("scope");
    if (scopes != null && scopes.contains("customer_position.read.all")) {
      auditService.recordBulkAccess(jwt.getClaimAsString("client_id"), customerId);
      return;
    }
    String subject = jwt.getClaimAsString("customer_id");
    if (!Objects.equals(subject, customerId)) {
      throw new BusinessException(HttpStatus.FORBIDDEN, List.of(Exceptions.TL0004));
    }
  }
}
```

Añadir además tests que verifiquen que un token del cliente A recibe 403 al solicitar el objeto del cliente B.

---

### SEC-003 — Secretos de proveedores y de base de datos versionados en el repositorio

> ### 🟡 Estado en v1.5 (re-verificado 2026-08-31) — **ATENUADO · Critical → High**
>
> La mayor parte de los secretos se ha externalizado. En los perfiles `cert`, `pre` y `pro` de los once servicios ya no hay ni un solo valor literal: todos son `${SEC_*}`. El refresh token OAuth2 de Celmedia **ha desaparecido** de `beemailboxes/…/constants/Constant.java`, que hoy solo contiene nombres de parámetro (`"client_secret"`, `"refresh_token"`).
>
> **Lo que queda**, y por eso el hallazgo no se cierra: dos ficheros conservan las credenciales reales como **valor por defecto** de la variable de entorno, que es una forma de versionado con una capa de indirección:
>
> ```yaml
> # cpe-nxhbsc-beclaims/src/main/resources/config/application-local.yml:19-20
> userName: ${SEC_CONTACTANOS_USER_NAME:apibookclaim}
> password: ${SEC_CONTACTANOS_PASSWORD:ApiB…Auth^&}      # 44 caracteres, en claro
>
> # cpe-nxhbsc-bewatchscreening/src/main/resources/config/application-local.yml:4,6
> secretKey: ${SEC_GESINTEL_SECRET_KEY:2074a479-…-a4113a097e1d}
> password:  ${SEC_GESINTEL_PASSWORD:3Kgp……rv1}
> ```
>
> Que estén en el perfil `local` no los hace inocuos: son credenciales **de proveedor**, no de un stub, y siguen en el historial de Git. **La rotación sigue siendo necesaria** — el valor está comprometido desde el momento en que se versionó, con independencia de qué perfil lo lea.


**Severidad:** Critical · **Confianza:** CONFIRMADO · **Prioridad:** P0
**CWE:** CWE-798 (Use of Hard-coded Credentials), CWE-540 (Inclusion of Sensitive Information in Source Code)
**OWASP:** API8:2023 Security Misconfiguration
**Proyecto/API:** beclaims, becreditrisk, becustombeprogrm, beemailboxes, beidentbiometric, bewatchscreening

#### Ubicación

```text
cpe-nxhbsc-beclaims/src/main/resources/config/application-local.yml:19-21
cpe-nxhbsc-becreditrisk/src/main/resources/config/application-local.yml:15-17, 23-26
cpe-nxhbsc-becustombeprogrm/src/main/resources/config/application-local.yml:13-17, 24-29
cpe-nxhbsc-beemailboxes/src/main/resources/config/application-local.yml:9-19
cpe-nxhbsc-beemailboxes/src/main/resources/config/application-cert.yml:11-12, 18
cpe-nxhbsc-beemailboxes/src/main/resources/config/application-pre.yml:11-12, 18
cpe-nxhbsc-beemailboxes/src/main/java/.../infrastructure/constants/Constant.java:28
cpe-nxhbsc-beidentbiometric/src/main/resources/config/application-local.yml:27-28
cpe-nxhbsc-bewatchscreening/src/main/resources/config/application-local.yml:4-6
cpe-nxhbsc-bedigitsignature/src/main/resources/config/application.yml (x-santander-client-id)
```

#### Descripción

Se localizaron credenciales con apariencia de ser reales, versionadas como valores por defecto de `${VAR:default}`. **No se han utilizado ni validado.** Se listan enmascaradas:

| Proyecto | Secreto | Ubicación | Valor (enmascarado) |
| -------- | ------- | --------- | ------------------- |
| beclaims | Password API Contáctanos | `application-local.yml:21` | `ApiB…####` (36 car.) |
| beclaims | Usuario API Contáctanos | `application-local.yml:20` | `apib…aim` |
| becreditrisk | Password RDS Postgres | `application-local.yml:17` | `Sx8F…KPxq` |
| becreditrisk | Usuario RDS Postgres | `application-local.yml:16` | `admi…oper` |
| becreditrisk | `client_secret` Modelica | `application-local.yml:25` | `kC?b…xrUP` (40 car.) |
| becreditrisk | `client_id` Modelica | `application-local.yml:24` | `bwuY…nM5` |
| becustombeprogrm | Clave AES (`aes.secret`) | `application-local.yml:14` | `9b7c…9d01` (64 hex) |
| becustombeprogrm | Secreto JWT (`jwt.secret`) | `application-local.yml:17` | **idéntico al anterior** |
| becustombeprogrm | Subscription key SKY | `application-local.yml:25` | `5cfc…1d2c` |
| beemailboxes | `client_secret` correo Celmedia | `local/cert/pre.yml` | `86ec…8e6c` |
| beemailboxes | **refresh_token OAuth2 Celmedia** | `local/cert/pre.yml` **y `Constant.java:28`** | `rMu4…OXsS1` |
| beemailboxes | `client_id` OTP Celmedia | `local/cert/pre.yml` | `cli_…7c7d` |
| beemailboxes | `client_secret` OTP Celmedia | `local/cert/pre.yml` | `sec_…d8c7` (64 hex) |
| beidentbiometric | API key FacePhi | `application-local.yml:27` | `hAGV…M7hf` (40 car.) |
| beidentbiometric | API key FacePhi (auth) | `application-local.yml:28` | `Xlap…ClPX` (40 car.) |
| bewatchscreening | Secret key Gesintel | `application-local.yml:4` | `2074…97e1d` (UUID) |
| bewatchscreening | Usuario Gesintel | `application-local.yml:5` | `serv…nder` |
| bewatchscreening | Password Gesintel | `application-local.yml:6` | `3Kgp…rv1` |

Tres agravantes:

**(a) `beemailboxes` no usa variables de entorno en CERT ni PRE.** En los demás proyectos los secretos aparecen solo como *default* de una variable (`${VAR:valor}`), lo que al menos permite sobrescribirlos. Aquí están escritos como literales:

```yaml
# cpe-nxhbsc-beemailboxes/src/main/resources/config/application-cert.yml:9-21
email:
  client-id: da3996aa-…
  client-secret: 86ecd30c-…          # literal, sin ${...}
  refresh-token: rMu4uG24_…          # literal, sin ${...}
otp:
  client-id: cli_2663…
  client-secret: sec_c66e…           # literal, sin ${...}
```

Los perfiles `cert` y `pre` **no pueden funcionar sin estos valores**, lo que indica que son los secretos operativos de esos entornos.

**(b) El refresh token también está en código Java**, fuera de cualquier gestión de configuración:

```java
// cpe-nxhbsc-beemailboxes/.../infrastructure/constants/Constant.java:28
public static final String REFRESH_VALUE = "rMu4uG24_…";
```

Un refresh token OAuth2 permite obtener access tokens indefinidamente hasta su revocación explícita.

**(c) La clave AES y la clave de firma JWT son el mismo valor** en `becustombeprogrm` (ver SEC-023). Comprometer una compromete la otra.

#### Source / Sink

No aplica flujo de datos: la exposición se produce por el propio versionado. El sink es el historial de Git, cada clon local, cada runner de CI, cada imagen de contenedor y cada artefacto en el repositorio Maven.

#### Escenario de explotación

Cualquier persona con acceso de lectura al repositorio — o a un fork, a un backup, al historial tras una rotación de permisos, o a la imagen del contenedor — obtiene credenciales válidas de los proveedores de biometría, AML, riesgo crediticio, OTP y correo, y de la base de datos de riesgo crediticio. Con la API key de FacePhi se puede operar contra la plataforma de identidad al margen del banco; con el refresh token de Celmedia, generar OTP y enviar correo desde la infraestructura del proveedor.

#### Impacto

* **Confidencialidad:** compromiso de todas las integraciones enumeradas, incluida una base de datos con datos crediticios.
* **Integridad:** capacidad de operar como el banco frente a proveedores de identidad y AML.
* **Negocio:** notificación obligatoria a los proveedores, rotación coordinada y posible incidente reportable.

#### Remediación

Es un incidente, no solo un defecto de código. Secuencia:

1. **Rotar de inmediato los 18 secretos listados**, coordinando con cada proveedor. Asumirlos comprometidos: han estado en un repositorio.
2. **Purgar el historial de Git** (`git filter-repo`) o, si no es viable, rotar y documentar formalmente la exposición. Rotar es suficiente si se hace primero.
3. **Eliminar los literales** y dejar únicamente la referencia sin valor por defecto, de forma que el arranque falle si falta el secreto:

```yaml
# Vulnerable
password: ${SEC_CONTACTANOS_PASSWORD:ApiBook!…}

# Recomendado
password: ${SEC_CONTACTANOS_PASSWORD}
```

4. **Eliminar `Constant.REFRESH_VALUE`** y obtener el refresh token del gestor de secretos:

```java
// Código vulnerable
public static final String REFRESH_VALUE = "rMu4uG24_…";

// Código recomendado
@ConfigurationProperties(prefix = "email")
public record EmailProperties(String clientId, String clientSecret,
                              String refreshToken, String urlSendMail, String uriApiToken) {}
```

5. Para desarrollo local, usar un `application-local.yml` **no versionado** (añadirlo a `.gitignore`) o un `.env` local, nunca valores por defecto en el árbol de fuentes.
6. Habilitar detección de secretos en el pipeline (`gitleaks` / `trufflehog`) como *gate* bloqueante en el workflow `security.yml`, que hoy solo ejecuta el análisis reutilizable de imagen.

---

### SEC-004 — Validación de certificado TLS deshabilitada en todas las salidas

> ### 🟡 Estado en v1.5 (re-verificado 2026-08-31) — **ATENUADO · 7 → 6 proyectos**
>
> `beemailboxes` **lo ha corregido**. Su `RestTemplateConfig` ya no usa `NoopHostnameVerifier` ni una `TrustStrategy` permisiva; ahora construye el contexto con `SSLContexts.createSystemDefault()` y `new DefaultHostnameVerifier()` (líneas 34-41), y restringe el protocolo a TLS 1.3/1.2. Los imports de `NoopHostnameVerifier` y `TrustStrategy` siguen ahí sin usarse — conviene borrarlos para que nadie los reactive.
>
> **Este es el patrón a replicar** en los seis restantes: `beclaims`, `becreditrisk`, `becustombeprogrm`, `bedigitsignature`, `beidentbiometric` y `bewatchscreening` mantienen `InsecureTrustManagerFactory.INSTANCE` sin cambios. La severidad se mantiene en Critical porque el defecto sigue vivo en los seis servicios que hablan con Modellica, FacePhi, Gesintel, SKY y Qurable.


**Severidad:** Critical · **Confianza:** CONFIRMADO · **Prioridad:** P0
**CWE:** CWE-295 (Improper Certificate Validation), CWE-297 (Improper Validation of Certificate with Host Mismatch)
**OWASP:** A02:2021 Cryptographic Failures
**Proyecto/API:** beclaims, becreditrisk, becustombeprogrm, bedigitsignature, beidentbiometric, bewatchscreening, beemailboxes

#### Ubicación

```text
beclaims          · WebClientConfig.java:52-54, 93-95
becreditrisk      · WebClientConfig.java:73-74, 98-99
becustombeprogrm  · WebClientConfig.java:23-25
bedigitsignature  · WebClientConfig.java:78-79
beidentbiometric  · WebClientConfig.java:53-54
bewatchscreening  · WebClientConfig.java:50-51, 92-93
beemailboxes      · RestTemplateConfig.java:31-42
```

#### Descripción

Seis servicios construyen su `SslContext` con el trust manager de pruebas de Netty, que **acepta cualquier certificado**:

```java
// beidentbiometric/WebClientConfig.java:53-54
var sslContext =
    SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();
```

`beemailboxes` implementa lo mismo sobre Apache HttpClient 5 y **además desactiva la verificación de hostname**, con un comentario que confirma la intención:

```java
// beemailboxes/RestTemplateConfig.java:31-42
// Equivalente a InsecureTrustManagerFactory.INSTANCE
TrustStrategy trustStrategy = (chain, authType) -> true;

SSLContext sslContext = SSLContexts.custom()
        .loadTrustMaterial(null, trustStrategy)
        .build();

SSLConnectionSocketFactory sslSocketFactory =
        new SSLConnectionSocketFactory(
                sslContext,
                NoopHostnameVerifier.INSTANCE
        );
```

`(chain, authType) -> true` acepta cualquier cadena de certificación, incluidos certificados autofirmados o emitidos por una CA arbitraria. `NoopHostnameVerifier` elimina la comprobación de que el certificado corresponda al host solicitado.

Sobre estos canales viajan: API keys de FacePhi, la API key de Zytrust, `client_secret` de Modellica, credenciales de Gesintel, credenciales de Contáctanos, tokens OAuth2 de Celmedia, imágenes faciales, documentos de identidad y PDFs contractuales.

**Causa raíz probable y por qué la solución adoptada es incorrecta.** El diagrama muestra que la salida a terceros atraviesa `Transit Gateway → Firewall Norte → Netskope → Terceros`. Netskope es un Secure Web Gateway que realiza **inspección TLS**: termina la conexión, la reinspecciona y la vuelve a emitir con un certificado firmado por su propia CA. Un cliente que confíe únicamente en las CA públicas rechazará ese certificado con `PKIX path building failed`.

Es casi seguro que ese error fue el motivo por el que se introdujo `InsecureTrustManagerFactory`. La solución correcta ante ese síntoma es **añadir la CA de Netskope al truststore**, no aceptar cualquier certificado: al hacer trust-all, el servicio pierde la capacidad de distinguir el MITM legítimo y autorizado de Netskope de cualquier otro MITM no autorizado en la ruta. El control corporativo de inspección queda intacto; lo que se pierde es toda garantía adicional.

Agravante: los clientes salen además a través de un proxy HTTP (`proxy.sig.umbrella.com:443`), lo que suma otro punto de terminación en la cadena.

#### Flujo

```text
Microservicio
   ↓ HttpClient con trust-all + (beemailboxes) sin verificación de hostname
Proxy corporativo
   ↓
Internet
   ↓
Proveedor externo (FacePhi / Zytrust / Modelica / Gesintel / Celmedia)
```

Cualquier nodo en esa ruta que pueda interceptar la conexión presenta su propio certificado y es aceptado.

#### Source

No aplica: es un defecto de configuración criptográfica, no un flujo de datos controlado por el atacante.

#### Sink

Toda comunicación TLS saliente de los siete servicios.

#### Escenario de explotación

Un atacante con posición de red (proxy comprometido, DNS envenenado, workload malicioso en el clúster, o un intermediario en el tránsito hacia el proveedor) presenta un certificado propio. El cliente lo acepta sin objeción, y el atacante obtiene en claro las credenciales del proveedor y los datos biométricos y documentales en tránsito, además de poder alterar las respuestas — por ejemplo, convertir un `liveness` fallido en satisfactorio.

#### Impacto

* **Confidencialidad:** exposición en tránsito de credenciales y de datos biométricos y documentales.
* **Integridad:** manipulación de las respuestas de los proveedores de identidad y AML, con impacto directo en decisiones de onboarding y de riesgo.
* **Cumplimiento:** anula el propósito del cifrado en tránsito exigido por la normativa interna.

#### Remediación

Eliminar el trust-all y usar el almacén de confianza del sistema (que ya contiene la CA corporativa en la imagen base) o un truststore explícito:

```java
// Código vulnerable
var sslContext =
    SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();

HttpClient httpClient = HttpClient.create()
        .secure(t -> t.sslContext(sslContext)
                      .handlerConfigurator((SslHandler sslHandler) -> {}));  // desactiva el hostname check
```

```java
// Código recomendado
@Bean
public HttpClient httpClient(SslProperties props) throws Exception {
  KeyStore trustStore = KeyStore.getInstance("PKCS12");
  try (InputStream in = Files.newInputStream(Path.of(props.trustStorePath()))) {
      trustStore.load(in, props.trustStorePassword().toCharArray());
  }
  TrustManagerFactory tmf =
      TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
  tmf.init(trustStore);

  SslContext sslContext = SslContextBuilder.forClient()
          .trustManager(tmf)
          .protocols("TLSv1.3", "TLSv1.2")
          .build();

  return HttpClient.create()
          .secure(spec -> spec.sslContext(sslContext));   // sin handlerConfigurator vacío:
                                                          // conserva la verificación de hostname
}
```

Para `beemailboxes`:

```java
// Código recomendado
SSLContext sslContext = SSLContexts.createSystemDefault();
SSLConnectionSocketFactory sslSocketFactory =
        new SSLConnectionSocketFactory(sslContext, HttpsSupport.getDefaultHostnameVerifier());
```

Nota sobre `handlerConfigurator((SslHandler sslHandler) -> {})`: en Reactor Netty ese lambda vacío **reemplaza** la configuración por defecto que activa `HTTPS` endpoint identification. Debe eliminarse aunque se corrija el trust manager.

**Truststore recomendado para este entorno:** construir en la imagen del contenedor un truststore que contenga (a) las CA públicas del sistema y (b) **la CA de inspección de Netskope** y la del proxy corporativo. Con eso, la validación queda activa y las conexiones inspeccionadas se aceptan legítimamente:

```dockerfile
# Dockerfile — recomendado (capa adicional sobre la imagen base corporativa)
COPY --chown=java:java certs/netskope-ca.pem /tmp/netskope-ca.pem
RUN keytool -importcert -noprompt -trustcacerts \
      -alias netskope-ca -file /tmp/netskope-ca.pem \
      -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit \
 && rm /tmp/netskope-ca.pem
```

Si algún proveedor usa además un certificado emitido por una CA privada propia, importarla igualmente. Si el requisito es mTLS, configurar `keyManager` con el certificado de cliente — nunca desactivar la validación del servidor.

Añadir una regla de calidad que falle el build ante `InsecureTrustManagerFactory`, `NoopHostnameVerifier` o `TrustStrategy` permisiva.

---

### SEC-005 — Bypass del segundo factor: validación de OTP sin vínculo al usuario, sin límite de intentos y con el código en el path y en los logs

> ### 🔴 Estado en v1.6 (re-verificado 2026-09-03) — **PERSISTE · remediación incompleta**
>
> Se intentó corregir el punto (2) de este hallazgo y **la corrección quedó inerte**. `JsonApiClient.validOTP` ya no devuelve el `message` del proveedor: ahora evalúa de verdad el veredicto de Celmedia.
>
> ```java
> // JsonApiClient.java:56-77  — CORREGIDO: ya se interpreta el veredicto
> if (response.hasBody()){
>     ValidateOtp validateOtp = response.getBody().getData();
>     return validateOtp.getStatus().equals("validated") && validateOtp.isValid() ? "Valid" : "Invalid";
> }
> return "Invalid";
> ```
>
> Pero el llamante **no se tocó**:
>
> ```java
> // OTPServiceAdapter.java:61-71  — SIN CAMBIOS
> String status = jsonApiClient.validOTP(generateValidateOtp(otp));
> if (status != null) {                                    // <-- "Valid" y "Invalid" son ambos != null
>     return generateResponsseValidCode(StatusInfo.StatusCodeEnum.PROCESSED);
> } else {
>     return generateResponsseValidCode(StatusInfo.StatusCodeEnum.ERROR);
> }
> ```
>
> El método ahora devuelve **siempre** una cadena no nula — `"Valid"` o `"Invalid"` —, de modo que la rama `else` es código muerto y **toda validación de OTP responde `PROCESSED`, incluida la de un código incorrecto**. El defecto no solo sigue ahí: está peor, porque el código aparenta validar y una revisión rápida del `git diff` de `JsonApiClient` lo daría por resuelto.
>
> **La corrección es de una línea:** `if ("Valid".equals(status))`. Está en §17 (Quick Wins).
>
> Se confirma además, en el mismo ciclo:
>
> * **El OTP sigue siendo la partition key** de la tabla DynamoDB (`OtpEntity:31-35`, con los getters cruzados — ver SEC-051), luego un código válido de cualquier usuario sigue sirviendo para superar la validación de cualquier operación.
> * **No hay TTL ni marca de consumo** en `OtpEntity`: un OTP generado hoy sigue en la tabla indefinidamente y admite reutilización. `BaseDynamoRepository.putIfAbsent` escribe sin `ttl` y nada borra ni invalida el registro tras su uso.
> * **El OTP se escribe en claro tres veces** por flujo: `OTPServiceAdapter:101` (`"OTP generado: {}"`), `OTPServiceAdapter:116` (el `RequestOTP` completo, que es `@Data` y arrastra el código concatenado por `setearOtp`) y `XmlApiClient:44` (el XML entero enviado a Celmedia).
> * **El OTP sigue viajando en el path**: `EmailboxIdApiDelegateImpl:51-56` pasa el path variable `email_id` como código a `validCode`.
>
> Se añadió un rate limiter, pero solo sobre la generación — ver SEC-053.

**Severidad:** Critical · **Confianza:** CONFIRMADO · **Prioridad:** P0
**CWE:** CWE-304 (Missing Critical Step in Authentication), CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-532 (Insertion of Sensitive Information into Log File), CWE-598 (Use of GET Request Method With Sensitive Query Strings)
**OWASP:** API2:2023 Broken Authentication
**Proyecto/API:** cpe-nxhbsc-beemailboxes

#### Ubicación

```text
Archivo: cpe-nxhbsc-beemailboxes/src/main/java/.../infrastructure/adapters/output/OTPServiceAdapter.java
Clase:   OTPServiceAdapter
Metodos: validCode(String, WrapperRequestClassifyEmails)  · lineas 60-70
         generateValidateOtp(String)                      · lineas 72-80
         sendMailing(WrapperRequestSendEmail, String)      · lineas 89-118
Archivo: cpe-nxhbsc-beemailboxes/src/main/java/.../infrastructure/adapters/input/rest/EmailboxIdApiDelegateImpl.java:50-56
Archivo: cpe-nxhbsc-beemailboxes/src/main/java/.../infrastructure/client/XmlApiClient.java:44,47
Contrato: cpe-nxhbsc-beemailboxes/src/main/resources/openapi.yaml — POST /{emailbox_id}/emails/{email_id}/classify_email
```

#### Descripción

Cuatro defectos concurrentes rompen el segundo factor.

**(1) La validación no vincula el OTP con ningún usuario ni sesión.**

```java
// OTPServiceAdapter.java:60-80
@Override
public WrapperClassifyEmail validCode(String otp, WrapperRequestClassifyEmails criteria) {

    String status = jsonApiClient.validOTP(generateValidateOtp(otp));

    if (status != null) {
        return generateResponsseValidCode(StatusInfo.StatusCodeEnum.PROCESSED);
    } else {
        return generateResponsseValidCode(StatusInfo.StatusCodeEnum.ERROR);
    }
}

private ValidateOtpRequest generateValidateOtp(String otp){
    String uuid = "";
    var optionalEntity = repository.getByKey(otp,null);
    if(optionalEntity.isEmpty()){
        return new ValidateOtpRequest();       // <-- sigue llamando al proveedor con request vacío
    }
    uuid = optionalEntity.get(0).getId();
    return new ValidateOtpRequest(uuid, otp);
}
```

El OTP es la *partition key* de la tabla DynamoDB. Se busca el código, se recupera **el `uuid` que le corresponda a quien sea**, y se valida esa pareja. El `criteria` recibido no se usa. No hay identidad, contrato, sesión ni destinatario contra el que contrastar: **un OTP válido de cualquier usuario sirve para superar la validación de cualquier operación**.

**(2) La condición de éxito es `status != null`.**

`validOTP` devuelve `response.getBody().getMessage()` — un texto del proveedor:

```java
// JsonApiClient.java:59-76
public String validOTP(ValidateOtpRequest request){
    ...
    ResponseEntity<ValidateOtpResponse> response = restTemplate.postForEntity(
            otpProperties.getValidateUrl(),entity, ValidateOtpResponse.class);
    return Objects.requireNonNull(response.getBody()).getMessage();
}
```

Cualquier `message` no nulo — incluido `"OTP inválido"` o `"expirado"` — produce `PROCESSED`. La validación no comprueba un código de resultado, comprueba que el proveedor haya respondido algo.

**(3) El OTP viaja en la ruta de la URL.**

```java
// EmailboxIdApiDelegateImpl.java:50-56
@Override
public ResponseEntity<WrapperClassifyEmail> createEmailboxEmailClassify(String emailboxId,
                                                                 String emailId,
                                                                 WrapperRequestClassifyEmails criteria) {
    return ResponseEntity.ok(emailboxIdInputPort
            .validCode(emailId, criteria));      // emailId (path variable) ES el OTP
}
```

La ruta es `POST /v1/emailboxes/{emailbox_id}/emails/{email_id}/classify_email`. El parámetro documentado como identificador de correo es en realidad el código de un solo uso. Las URLs se registran en los access logs del ingress, del API Gateway, del proxy y en las trazas de APM.

**(4) El OTP se escribe en claro en los logs, dos veces.**

```java
// OTPServiceAdapter.java:98-114
log.info("Antes de generar OTP: {}", uuid);
String otp = jsonApiClient.generarOTP(uuid);
log.info("OTP generado: {}",otp);                    // <-- OTP en claro
repository.putIfAbsent(new OtpEntity(uuid,otp));
requestOTP = setearOtp(requestOTP, otp);
...
log.info("Antes de enviar correo: {}", requestOTP);   // <-- OTP + destinatario
```

```java
// XmlApiClient.java:44,47
log.info("antes de llamar al api: {}", entity.getBody());   // XML completo con el OTP
log.info("despues de llamar al api: {}", response.getBody());
```

`RequestOTP` es un `@Data` de Lombok, por lo que `{}` imprime todos sus campos, incluida la personalización que contiene el código concatenado (`setearOtp`, líneas 155-162) y el correo del destinatario.

**(5) No hay límite de intentos ni de generación.** No existe contador de intentos fallidos, bloqueo, ni rate limiting (SEC-019). Y el endpoint que **genera** el OTP y envía el correo tampoco está autenticado (SEC-001).

#### Flujo

```text
POST /v1/emailboxes/{emailbox_id}/send_email   (sin autenticación)
   ↓
OTPServiceAdapter.sendMailing(..., flow="otp")
   ↓  genera OTP en Celmedia, lo persiste en DynamoDB con el OTP como PK,
      lo escribe en el log y lo envía por correo
   ↓
POST /v1/emailboxes/{id}/emails/{OTP}/classify_email   (sin autenticación)
   ↓
OTPServiceAdapter.validCode(otp, criteria)
   ↓  repository.getByKey(otp)  ← sin comprobar de quién es el OTP
   ↓  jsonApiClient.validOTP(...)  →  message != null
   ↓
StatusCodeEnum.PROCESSED
```

#### Source

* `email_id` (path variable) — el código OTP, totalmente controlado por el solicitante.
* Cuerpo de `send_email` — destinatario del correo, controlado por el solicitante.

#### Sink

Respuesta `PROCESSED` que el consumidor interpreta como segundo factor superado; y persistencia/envío del OTP.

#### Escenario de explotación

Tres vías, todas viables:

* **Reutilización cruzada.** El atacante solicita un OTP para su propia dirección de correo mediante `send_email` (endpoint no autenticado), lo recibe, y lo presenta en `classify_email` para autorizar una operación asociada a otra persona. El código no comprueba a quién pertenece el OTP.
* **Fuerza bruta.** Los códigos residen en una tabla indexada por el propio código. Sin límite de intentos ni rate limiting, un barrido concurrente encuentra códigos activos de otros usuarios.
* **Lectura de logs.** Quien tenga acceso al agregador de logs (equipos de soporte, observabilidad, o cualquier compromiso de esa plataforma) lee los OTP en claro conforme se generan, en tiempo real.

#### Impacto

* **Integridad / negocio:** anulación del segundo factor. Cualquier operación que dependa de esta validación queda autorizable por un tercero.
* **Confidencialidad:** OTP, direcciones de correo y contenido de los mensajes expuestos en logs.
* **Disponibilidad y coste:** generación ilimitada de OTP y correos contra la cuota del proveedor, y uso de la infraestructura del banco para enviar correo a destinatarios arbitrarios.

#### Remediación

Rediseño del flujo. Los cuatro cambios son necesarios; ninguno basta por sí solo.

**1. Vincular el OTP a una operación y a un sujeto.** La clave debe ser el identificador de la operación, no el código:

```java
// Código vulnerable
var optionalEntity = repository.getByKey(otp, null);   // busca POR el OTP
uuid = optionalEntity.get(0).getId();

// Código recomendado
@Override
public WrapperClassifyEmail validCode(String transactionId, String otp, String subjectId) {
    OtpEntity entity = repository.getByKey(transactionId, null)          // PK = transactionId
            .orElseThrow(() -> new BusinessException(HttpStatus.UNAUTHORIZED, List.of(Exceptions.TL0003)));

    if (!Objects.equals(entity.getSubjectId(), subjectId)) {             // el OTP es de otro
        throw new BusinessException(HttpStatus.FORBIDDEN, List.of(Exceptions.TL0004));
    }
    if (entity.getAttempts() >= MAX_ATTEMPTS || Instant.now().isAfter(entity.getExpiresAt())) {
        repository.invalidate(transactionId);
        throw new BusinessException(HttpStatus.UNAUTHORIZED, List.of(Exceptions.TL0003));
    }
    repository.incrementAttempts(transactionId);

    ValidateOtpResponse result = jsonApiClient.validOTP(new ValidateOtpRequest(entity.getId(), otp));
    if (!result.isValid()) {                                             // código de resultado, no != null
        return generateResponsseValidCode(StatusInfo.StatusCodeEnum.ERROR);
    }
    repository.consume(transactionId);                                   // un solo uso
    return generateResponsseValidCode(StatusInfo.StatusCodeEnum.PROCESSED);
}
```

**2. Sacar el OTP del path.** Debe viajar en el cuerpo de un `POST`, y el contrato debe corregirse:

```yaml
# openapi.yaml — recomendado
/otp/{transaction_id}/verify:
  post:
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [code]
            properties:
              code:
                type: string
                pattern: '^[0-9]{6,8}$'
                maxLength: 8
```

**3. Eliminar el OTP de los logs.**

```java
// Código vulnerable
log.info("OTP generado: {}",otp);
log.info("Antes de enviar correo: {}", requestOTP);

// Código recomendado
log.info("OTP generado para transactionId={} (destinatario enmascarado: {})",
         transactionId, mask(recipient));
```

Y en `XmlApiClient`, sustituir el volcado del cuerpo por metadatos:

```java
// Código recomendado
log.debug("Envío a proveedor: transactionId={}, bytes={}", transactionId, xmlBody.length());
```

**4. Aplicar límites**: intentos por transacción (3-5), generación por sujeto y por ventana temporal, y expiración corta (TTL de DynamoDB). Ver SEC-019.

---

### SEC-006 — Callback del flujo de firma digital dirigido a `webhook.site` y token de callback literal `jwt`

> ### ⏸️ APLAZADO en v1.7 (2026-09-03) — fuera del alcance de este Ethical Hacking
>
> El componente `cpe-nxhbsc-bedigitsignature` entra en el EH **solo por su API de solicitud de firma**; la **recepción** del documento firmado — el callback de retorno, que es de lo que trata este hallazgo — queda fuera.
>
> **Pero conviene no perder de vista una mitad de este hallazgo.** Que la URL de retorno apunte a `webhook.site` **la emite el API de solicitud, que sí está en alcance**: es `signtureDocument` quien envía esa URL al proveedor, y basta una llamada al endpoint que el EH sí va a ejecutar para que el documento firmado acabe en un servicio público de terceros. Lo puramente de recepción es la otra mitad: autenticar el callback con la cadena literal `jwt`. **La corrección de la URL no debería esperar** — cuesta una propiedad de entorno y está en §17.
>
> **El hallazgo sigue siendo válido y sigue abierto.** No se ha corregido nada: el código permanece desplegado y el defecto es explotable por quien tenga acceso a ese componente. Lo único que cambia es que **no se mide contra este ejercicio** y no cuenta en los 47 hallazgos de alcance — sí en los 56 de deuda técnica. Se conserva íntegro, con su evidencia y su remediación, para que al volver a alcance recupere su historial en lugar de reaparecer como hallazgo nuevo.

**Severidad:** Critical · **Confianza:** CONFIRMADO · **Prioridad:** P0
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-306, CWE-798, CWE-1188
**OWASP:** API8:2023 Security Misconfiguration · API2:2023 Broken Authentication
**Proyecto/API:** cpe-nxhbsc-bedigitsignature

#### Ubicación

```text
Archivo: cpe-nxhbsc-bedigitsignature/src/main/java/.../infrastructure/utils/Constant.java
Lineas:  64-65
Archivo: cpe-nxhbsc-bedigitsignature/src/main/java/.../infrastructure/adapters/output/DocumentProcessService.java
Metodo:  buildSignatureRequest(String, String, ApplicationSignatureRequest, String)
Lineas:  64-73, 87-109
Archivo: cpe-nxhbsc-bedigitsignature/src/main/java/.../infrastructure/utils/JwtUtil.java:30-47
```

#### Descripción

Dos defectos en el mismo punto del flujo de firma.

**(a) La URL de callback apunta a un servicio público de terceros.**

```java
// Constant.java:64-65
public static final String CALLBACK = "https://webhook.site/#!/view/b9857938-cd5d-4a17-8387-7f2d1fbe8e29";
public static final String HEADERS = "Authorization=Bearer jwt;Content-Type=application/json";
```

`webhook.site` es un servicio gratuito de captura de webhooks para pruebas. Esta URL se envía al proveedor de firma en cada solicitud.

**El diagrama de arquitectura confirma la gravedad de dos formas.** Primera: la salida hacia terceros pasa por `Firewall Norte → Netskope`, de modo que las peticiones que registran este callback ante el proveedor atraviesan y quedan registradas en el control de navegación corporativo con destino a un dominio de captura pública. Segunda, y más relevante: **el diagrama no contempla ninguna ruta de entrada desde los proveedores hacia el VPC** — todas las flechas hacia terceros son salientes. No existe un endpoint de callback publicado en el API Gateway para recibir la notificación de firma. Es decir, el flujo de firma digital **no tiene diseñado su camino de retorno**, y el código lo ha rellenado provisionalmente con un servicio de pruebas de terceros que quedó en el árbol productivo.

La URL se envía al proveedor de firma en cada solicitud:

```java
// DocumentProcessService.java:64-73
private Signer buildSignatureRequest(String documentId, String document,
                                     ApplicationSignatureRequest client, String jwt) {
    String headers = Constant.HEADERS.replace("JWT",jwt);
    List<String> signature = List.of(client.getNombre(),client.getApellido(),client.getDni());
    ApplicationSignDocumentRequestInner docIten = client.getDocumentos().stream()
            .filter(doc->documentId.equals(doc.getIdDocumento())).findFirst().get();
    return new Signer(document, docIten.getPage(), docIten.getPosition(),
                      signature, Constant.CALLBACK, headers);
}
```

El proveedor enviará la notificación de firma completada —con el identificador del documento, el estado y los datos que el proveedor incluya— a un endpoint fuera del control del banco. La URL contiene además un fragmento `#!/view/...`, propio de la interfaz web del servicio, no de su endpoint de recepción: la notificación no llegará a ningún sistema del banco, con lo que el flujo también queda funcionalmente incompleto.

**(b) El token del callback nunca se sustituye.**

`Constant.HEADERS` contiene el marcador en minúsculas (`Bearer jwt`) pero `replace` busca la cadena en mayúsculas (`"JWT"`). La cadena `"JWT"` no aparece en `"Authorization=Bearer jwt;Content-Type=application/json"`, por lo que **`replace` no sustituye nada** y el header enviado al proveedor es literalmente:

```text
Authorization=Bearer jwt
```

El JWT que sí se genera (`jwtUtil.generateToken()`, línea 87) nunca se transmite: solo se persiste en DynamoDB (línea 107) y se escribe en el log (línea 106, ver SEC-007).

Añadido: aunque el bug se corrigiera, el token tendría **20 segundos de validez** pese a que el comentario indica una hora:

```java
// JwtUtil.java:38-39
long now = System.currentTimeMillis();
long expiration = now + 1000 * 20; // 1 hora
```

Un callback de firma se dispara cuando la persona firma, lo que puede tardar minutos u horas. El token estaría siempre expirado.

#### Flujo

```text
POST /v1/signature/signer  (sin autenticación, SEC-001)
   ↓
DocumentProcessService.signtureDocument()
   ↓
buildSignatureRequest()  →  callbackUrl = https://webhook.site/…
                            callbackHeaders = "Authorization=Bearer jwt"
   ↓
SignatureClient.signDocument()  →  POST {FACEPHI_BASE_URL}/signer
   ↓
Proveedor de firma almacena el callback y, al completarse la firma,
notifica a webhook.site con un bearer trivial
```

#### Source

Configuración estática del código (`Constant.CALLBACK`, `Constant.HEADERS`).

#### Sink

Petición HTTP saliente hacia el proveedor de firma, que registra el callback; y posteriormente la notificación del proveedor hacia el dominio de terceros.

#### Escenario de explotación

Quien conozca el identificador del webhook —presente en el repositorio— accede al panel público de `webhook.site` y observa las notificaciones de firma de documentos contractuales del banco: identificadores de documento, lotes, estados y cualquier metadato que el proveedor incluya. La URL es un UUID, pero está publicada en el código fuente, de modo que no ofrece protección alguna.

En sentido inverso, si el flujo se corrigiera para apuntar a un endpoint real del banco manteniendo `Bearer jwt` como credencial, **cualquiera podría invocar el callback** y declarar documentos como firmados: el token es una constante conocida.

#### Impacto

* **Confidencialidad:** metadatos de operaciones de firma de contratos enviados a un servicio público de terceros.
* **Integridad:** el flujo de firma no cierra correctamente; y el esquema de autenticación del callback es nulo.
* **Negocio:** un proceso con valor probatorio (firma electrónica de contratos) depende de una infraestructura de pruebas ajena.

#### Remediación

```java
// Código vulnerable
public static final String CALLBACK = "https://webhook.site/#!/view/b9857938-…";
public static final String HEADERS  = "Authorization=Bearer jwt;Content-Type=application/json";
...
String headers = Constant.HEADERS.replace("JWT", jwt);
```

```java
// Código recomendado — properties externalizadas
@ConfigurationProperties(prefix = "clients.signature")
public record SignatureApiProperties(
        String baseUrl,
        String xApiKey,
        String callbackUrl,       // endpoint propio del banco, por entorno
        Integer callbackTtlSeconds
) {}
```

```java
// Código recomendado — construcción del header sin marcadores frágiles
private Signer buildSignatureRequest(String documentId, String document,
                                     ApplicationSignatureRequest client, String jwt) {

    String headers = "Authorization=Bearer " + jwt + ";Content-Type=application/json";

    ApplicationSignDocumentRequestInner docItem = client.getDocumentos().stream()
            .filter(doc -> documentId.equals(doc.getIdDocumento()))
            .findFirst()
            .orElseThrow(() -> new BusinessException(HttpStatus.BAD_REQUEST,
                                                     List.of(Exceptions.TL0002)));   // ver SEC-028

    return new Signer(document, docItem.getPage(), docItem.getPosition(),
                      List.of(client.getNombre(), client.getApellido(), client.getDni()),
                      properties.callbackUrl(), headers);
}
```

```java
// Código recomendado — JWT de callback con vida útil realista y claims verificables
public String generateCallbackToken(String loteId, String documentId) {
    Instant now = Instant.now();
    return Jwts.builder()
            .issuer("cpe-nxhbsc-bedigitsignature")
            .audience().add("signature-callback").and()
            .subject(loteId)
            .id(UUID.randomUUID().toString())               // jti, para anti-replay
            .claim("documentId", documentId)
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plus(properties.callbackTtlSeconds(), ChronoUnit.SECONDS)))
            .signWith(secretKey, Jwts.SIG.HS256)
            .compact();
}
```

Y adicionalmente:

1. **Diseñar y publicar la ruta de entrada del callback**, hoy ausente en la arquitectura: exponer un endpoint dedicado en el API Gateway (por ejemplo `/v1/signature/callback`), protegido por Imperva y el WAF como el resto del tráfico entrante, y con una política de origen restringida a los rangos IP del proveedor de firma.
2. Implementar ese endpoint **validando la firma del JWT, `iss`, `aud`, `exp` y `jti`** (rechazando `jti` ya consumidos — ver SEC-037). El registro en DynamoDB debe pasar de indexarse por el JWT (SEC-031) a indexarse por `loteId`, y el callback debe localizar el lote por el `sub` del token, no por el token en sí.
3. Externalizar `callbackUrl` por entorno y prohibir por política dominios de terceros en su valor.
4. Añadir una regla de calidad que impida literales de dominios públicos de pruebas (`webhook.site`, `requestbin`, `ngrok`, `pipedream`) en el código.
5. Mientras el endpoint no exista, **el flujo de firma no debe considerarse operativo**: hoy no hay forma de que el banco se entere de que un documento fue firmado.

---

### SEC-007 — Credenciales, tokens de acceso y clave criptográfica escritos en los logs

**Severidad:** Critical · **Confianza:** CONFIRMADO · **Prioridad:** P0
**CWE:** CWE-532 (Insertion of Sensitive Information into Log File), CWE-522
**OWASP:** API8:2023 Security Misconfiguration
**Proyecto/API:** beclaims, becreditrisk, becustombeprogrm, bedigitsignature

#### Ubicación

```text
beclaims          · TokenService.java:50                 · log.warn("authRequest: {}", authRequest.toString())
becreditrisk      · TokenService.java:87                 · log.warn("CachedToken valid: {}", cachedToken.toString())
becustombeprogrm  · AesEncryptionService.java:33         · log.info("... method={}", transformation, aesProperties.getSecret())
bedigitsignature  · DocumentProcessService.java:106      · log.info("Antes de guardar en DynamoDB: jwt = {}, ...", jwt, loteId)
```

#### Descripción

Cuatro fugas distintas, todas confirmadas por el efecto de las anotaciones Lombok en los DTO implicados.

**(a) Contraseña de integración de Contáctanos (beclaims).**

```java
// TokenService.java:45-50
private synchronized void refreshToken(){
    if(cachedToken!= null){ return; }
    var authRequest = buildAuthRequest();
    log.warn("authRequest: {}", authRequest.toString());
```

```java
// AuthRequest.java:16-27
@Getter @Setter @AllArgsConstructor @NoArgsConstructor @Builder
@ToString                                   // <-- genera toString() con todos los campos
public class AuthRequest {
    @JsonProperty(value = "User")        private String user;
    @JsonProperty(value = "Contrasenia") private String password;
}
```

`@ToString` sin `@ToString.Exclude` produce `AuthRequest(user=…, password=…)`. La contraseña queda en el log en cada renovación de token, en nivel `WARN` (siempre activo con `root: WARN`).

**(b) Access token OAuth2 de Modelica (becreditrisk).**

```java
// TokenService.java:83-87
cachedToken =
    new CachedToken(
        tokenResponse.getToken(), Instant.now().plusSeconds(tokenResponse.getExpiresIn() - 30));

log.warn("CachedToken valid: {}", cachedToken.toString());
```

```java
// CachedToken.java:8-13
@Data                        // <-- @Data incluye @ToString
@AllArgsConstructor
public class CachedToken {
  private String accessToken;
  private Instant expirationTime;
}
```

El bearer completo del motor de riesgo crediticio se escribe en el log, junto con su momento de expiración — lo que indica al lector exactamente durante cuánto tiempo es utilizable.

**(c) Clave AES de cifrado del payload (becustombeprogrm).**

```java
// AesEncryptionService.java:31-35
public String encrypt(String value){
    String transformation = resolveTransformation();
    log.info("Iniciando encriptacion de payload. alg={}, method={}", transformation, aesProperties.getSecret());
```

El mensaje tiene dos marcadores `{}` y se pasan dos argumentos: el segundo, rotulado como `method`, es en realidad `aesProperties.getSecret()` — la clave AES en hexadecimal. Se registra en cada cifrado. Y por SEC-023, esa misma clave es el secreto de firma JWT del servicio.

**(d) JWT de callback de firma (bedigitsignature).**

```java
// DocumentProcessService.java:105-109
private Mono<String> saveDynamo(String loteId, String jwt, String documentId,String status){
    log.info("Antes de guardar en DynamoDB: jwt = {}, loteId = {} ", jwt,loteId);
    repository.putIfAbsent(new Entity(jwt,documentId,loteId,status));
    return Mono.just("data guardado");
}
```

#### Flujo

```text
Operación de negocio
   ↓
TokenService / AesEncryptionService / DocumentProcessService
   ↓
SLF4J → formato GLUONLOG → stdout del contenedor
   ↓
Agregador de logs corporativo (retención prolongada, acceso amplio)
```

#### Source

No aplica: los valores provienen de la configuración interna, no de entrada del atacante. El vector es el acceso a los registros.

#### Sink

Sistema de logs centralizado.

#### Escenario de explotación

Cualquier persona con acceso de lectura al agregador de logs —perfil habitualmente concedido de forma amplia a desarrollo, soporte y observabilidad, y objetivo frecuente en un compromiso— extrae con una consulta simple la contraseña de Contáctanos, los bearer de Modelica, la clave AES y los JWT de firma. No requiere acceso al repositorio ni a los pods.

Adicionalmente, los logs se conservan típicamente mucho más que la vida útil de un token, y sobreviven a la rotación de credenciales si esta no va acompañada de una purga.

#### Impacto

* **Confidencialidad:** compromiso de credenciales de integración y de material criptográfico.
* **Integridad:** con la clave AES/JWT de `becustombeprogrm` es posible falsificar tokens hacia SKY y descifrar/forjar payloads.
* **Cumplimiento:** almacenamiento de secretos en sistemas de registro, fuera del ámbito del gestor de secretos.

#### Remediación

```java
// Código vulnerable (beclaims)
log.warn("authRequest: {}", authRequest.toString());

// Código recomendado — no registrar el objeto; y excluir el campo en el DTO
log.debug("Solicitando token de Contáctanos para el usuario configurado");
```

```java
// AuthRequest.java — recomendado
@Getter @Setter @AllArgsConstructor @NoArgsConstructor @Builder
@ToString
public class AuthRequest {
    @JsonProperty(value = "User")        private String user;
    @ToString.Exclude                                    // <-- nunca en toString()
    @JsonProperty(value = "Contrasenia") private String password;
}
```

```java
// Código vulnerable (becreditrisk)
log.warn("CachedToken valid: {}", cachedToken.toString());

// Código recomendado
log.debug("Token renovado, expira en {}s",
          Duration.between(Instant.now(), cachedToken.getExpirationTime()).toSeconds());
```

```java
// CachedToken.java — recomendado
@Data @AllArgsConstructor
public class CachedToken {
  @ToString.Exclude
  private String accessToken;
  private Instant expirationTime;
}
```

```java
// Código vulnerable (becustombeprogrm)
log.info("Iniciando encriptacion de payload. alg={}, method={}", transformation, aesProperties.getSecret());

// Código recomendado
log.debug("Iniciando cifrado de payload. alg={}", transformation);
```

```java
// Código vulnerable (bedigitsignature)
log.info("Antes de guardar en DynamoDB: jwt = {}, loteId = {} ", jwt, loteId);

// Código recomendado
log.info("Persistiendo estado de firma. loteId={}, documentId={}", loteId, documentId);
```

Medidas transversales:

1. Prohibir por convención el registro de objetos DTO completos; registrar campos concretos y no sensibles.
2. Añadir `@ToString.Exclude` a todo campo que contenga credenciales, tokens o datos personales, y revisar el uso de `@Data` en DTO de seguridad.
3. Configurar un *masking converter* en el appender GLUONLOG que redacte patrones conocidos (`Bearer\s+[A-Za-z0-9._-]+`, claves hexadecimales largas) como defensa en profundidad.
4. Rotar los secretos ya expuestos en logs (coincide con SEC-003) y purgar los índices de log correspondientes.

---

### SEC-008 — Datos personales reales de clientes versionados en `data.sql`

> ### ✅ Estado en v1.5 (re-verificado 2026-08-31) — **RESUELTO**
>
> El fichero `cpe-nxhbsc-becreditrisk/src/main/resources/data.sql` **no existe** en el árbol actual. Se ha comprobado por causa, no solo por ausencia:
>
> * `find cpe-nxhbsc-* -name "*.sql"` devuelve un único resultado en todo el repositorio, `bedatacomanagment/src/main/resources/schema.sql`, que es DDL sin datos.
> * No queda ninguna referencia a `data.sql` ni a `spring.sql.init` en la configuración de `becreditrisk`.
> * El proyecto sigue en el alcance y su `PersonEntity`/`CustomerScpEntity` siguen presentes, de modo que la desaparición no se explica por una exclusión ni por un movimiento de código.
>
> **Sigue pendiente lo que el fichero implica**, y no lo cierra la eliminación: si esos registros llegaron a un entorno compartido, hay que confirmar con el DPO que se purgaron de la base de datos y del historial de Git — borrar el fichero de `HEAD` no lo borra de los commits anteriores.


**Severidad:** Critical · **Confianza:** CONFIRMADO · **Prioridad:** P0
**CWE:** CWE-359 (Exposure of Private Personal Information), CWE-540
**OWASP:** API3:2023 Broken Object Property Level Authorization (exposición de datos)
**Proyecto/API:** cpe-nxhbsc-becreditrisk

#### Ubicación

```text
Archivo: cpe-nxhbsc-becreditrisk/src/main/resources/data.sql
Lineas:  1-54
Tabla:   CREDIT_RISK
```

#### Descripción

El fichero contiene 54 sentencias `INSERT` con registros de riesgo crediticio que presentan todas las características de datos productivos: números de documento reales, código de tipo de documento (171), periodo (202603) y clasificaciones de riesgo del negocio. Ejemplos (documentos parcialmente enmascarados):

```sql
INSERT INTO CREDIT_RISK (PERIODO, COD_TIPO_DOCUMENTO, NRO_DOCUMENTO, COD_CMA, REF_CMA)
VALUES (202603,171,'11274**','RCH_0002','UPLA - PLAFT');

INSERT INTO CREDIT_RISK (PERIODO, COD_TIPO_DOCUMENTO, NRO_DOCUMENTO, COD_CMA, REF_CMA)
VALUES (202603,171,'52377**','RCH_0001','UPLA - PEP');

INSERT INTO CREDIT_RISK (PERIODO, COD_TIPO_DOCUMENTO, NRO_DOCUMENTO, COD_CMA, REF_CMA)
VALUES (202603,171,'18820**','CMA_0012','Castigo, Deficiente o Peor en los últimos 48 meses');
```

La combinación de número de documento con marcas `UPLA - PLAFT` (prevención de lavado de activos), `UPLA - PEP` (persona expuesta políticamente) y clasificación de deuda constituye **dato personal sensible de la categoría más protegida**: asocia a una persona identificable con una sospecha de riesgo financiero o con exposición política.

No son datos sintéticos plausibles: los identificadores tienen longitudes variables y realistas y las clasificaciones corresponden a la taxonomía interna real (`CMA_0004`, `CMA_0010`, `CMA_0012`, `RCH_0001`, `RCH_0002`).

Aunque `spring.sql.init` no está activo en el perfil `pro` de este proyecto (`ddl-auto: validate` en los cuatro perfiles), **el problema no es la ejecución sino la presencia del fichero en el repositorio**, en el JAR y en la imagen del contenedor: el recurso está bajo `src/main/resources`, por lo que se empaqueta en todos los artefactos.

#### Flujo

```text
data.sql (src/main/resources)
   ↓ versionado en Git → historial, clones, forks, backups
   ↓ empaquetado en el JAR → imagen de contenedor → registro de imágenes
   ↓ accesible a cualquiera con acceso al repo, al artefacto o a la imagen
```

#### Source / Sink

No aplica flujo de datos de atacante. La exposición es directa por el propio versionado.

#### Escenario de explotación

Cualquier persona con acceso de lectura al repositorio, al artefacto Maven o a la imagen del contenedor obtiene un listado nominal (por documento) de personas marcadas como PEP o con alertas PLAFT. Esa información tiene valor directo para fraude dirigido, ingeniería social y extorsión, y su divulgación desde el banco constituye una brecha notificable.

#### Impacto

* **Confidencialidad:** exposición de datos personales de categoría sensible.
* **Cumplimiento:** infracción de la Ley 29733 de Protección de Datos Personales (Perú) y de la normativa interna de tratamiento de datos; posible obligación de notificación a la Autoridad Nacional de Protección de Datos Personales.
* **Reputacional:** alto, por la naturaleza PEP/PLAFT de los registros.

#### Remediación

1. **Eliminar `data.sql` del repositorio** y purgarlo del historial (`git filter-repo --path src/main/resources/data.sql --invert-paths`), o registrar formalmente la exposición si la purga no es viable.
2. Sustituirlo por datos sintéticos, con documentos claramente inválidos y en un fichero de **test**, nunca en `src/main/resources`:

```sql
-- src/test/resources/data-test.sql  (recomendado)
INSERT INTO CREDIT_RISK (PERIODO, COD_TIPO_DOCUMENTO, NRO_DOCUMENTO, COD_CMA, REF_CMA)
VALUES (202601, 171, '00000001', 'CMA_0012', 'Clasificación de prueba');
INSERT INTO CREDIT_RISK (PERIODO, COD_TIPO_DOCUMENTO, NRO_DOCUMENTO, COD_CMA, REF_CMA)
VALUES (202601, 171, '00000002', 'RCH_0001', 'Clasificación de prueba');
```

3. Restringir el empaquetado en el `pom.xml` para que los datos de prueba no lleguen nunca al artefacto:

```xml
<resource>
  <directory>${project.basedir}/src/main/resources</directory>
  <excludes>
    <exclude>data.sql</exclude>
  </excludes>
</resource>
```

4. Añadir al pipeline una comprobación que bloquee ficheros con patrones de datos personales (documentos, correos, teléfonos) en `src/main/resources`.
5. Escalar el hallazgo al Delegado de Protección de Datos para su evaluación como posible incidente.

---

### SEC-009 — Credenciales transmitidas por HTTP en claro hacia Contáctanos

> ### 🟡 Estado en v1.5 (re-verificado 2026-08-31) — **ATENUADO · High → Medium**
>
> Los perfiles `cert`, `pre` y `pro` ya no fijan la URL: `baseUrl: ${CONTACTANOS_BASE_URL}` sin valor por defecto, de modo que el esquema lo decide el despliegue y el servicio no arranca si falta. La `http://` literal solo persiste como defecto del perfil `local`:
>
> ```yaml
> # cpe-nxhbsc-beclaims/src/main/resources/config/application-local.yml:18
> baseUrl: ${CONTACTANOS_BASE_URL:http://180.194.16.235/api_new}
> ```
>
> Se rebaja a Medium porque el código ya no impone texto en claro en producción. **No se cierra** por dos razones: la credencial que viaja por ese canal sigue siendo la misma de SEC-003, y el código no verifica el esquema — si el despliegue inyecta una `http://`, `TokenService` la usará sin protestar. La comprobación de que la variable de entorno productiva apunta a `https://` está fuera del alcance del análisis estático y debe confirmarla el equipo de plataforma.


**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)
**OWASP:** A02:2021 Cryptographic Failures
**Proyecto/API:** cpe-nxhbsc-beclaims

> **Calibración con la arquitectura.** Evaluado solo desde el código, este hallazgo parecía Critical (credenciales en claro hacia una IP pública). El diagrama muestra que la ruta hacia Contáctanos es `Transit Gateway → Firewall Sur → GSNET → Sistemas Santander (Navarrete interno)`, es decir, **red corporativa interna, no Internet**. Eso reduce el conjunto de atacantes posibles y justifica rebajarlo a **High**. No lo elimina: sigue siendo tráfico con credenciales y datos personales sin cifrar atravesando varios saltos de red del grupo.

#### Ubicación

```text
Archivo: cpe-nxhbsc-beclaims/src/main/resources/config/application-local.yml:19
Archivo: cpe-nxhbsc-beclaims/src/main/java/.../infrastructure/adapters/output/client/TokenService.java:52-60, 69-74
Archivo: cpe-nxhbsc-beclaims/src/main/java/.../infrastructure/config/WebClientConfig.java:105-110
```

#### Descripción

El endpoint por defecto del proveedor Contáctanos utiliza **HTTP sin cifrar** contra una dirección IP:

```yaml
# application-local.yml:18-22
api:
  contactanos:
    baseUrl: ${CONTACTANOS_BASE_URL:http://180.194.16.235/api_new}
    userName: ${SEC_CONTACTANOS_USER_NAME:apibookclaim}
    password: ${SEC_CONTACTANOS_PASSWORD:ApiB…}
    timeout: ${CONTACTANOS_TIMEOUT:5000}
```

Sobre ese canal se envía la autenticación en el cuerpo de la petición:

```java
// TokenService.java:52-60, 69-74
var response = tokenWebClient.post()
        .uri(Constant.POST_TOKEN)
        .contentType(MediaType.parseMediaType("application/json; charset=utf-8"))
        .bodyValue(buildAuthRequest())
        ...

private AuthRequest buildAuthRequest() {
    return AuthRequest.builder()
            .user(apiProperties.getUserName())
            .password(apiProperties.getPassword())
            .build();
}
```

y a continuación el token obtenido se adjunta como `Authorization: Bearer` en cada llamada de negocio (`WebClientConfig:112-119`), también por HTTP. El `WebClient` se construye con `baseUrl(apiProperties.getBaseUrl())`, sin ninguna comprobación de que el esquema sea `https`.

El uso de una IP en lugar de un nombre DNS impide además cualquier validación de certificado si en algún momento se migrase a HTTPS.

Este hallazgo es coherente con el waiver de seguridad conocido para la API Contáctanos (endpoint UAT alojado en segmento productivo, con plan de remediación por migración). El presente informe lo documenta desde el código: el defecto está codificado como valor por defecto de la aplicación.

#### Flujo

```text
beclaims (pod)
   ↓ POST http://180.194.16.235/api_new/…  {"User":"…","Contrasenia":"…"}   ← texto plano
Red corporativa
   ↓
Contáctanos
   ↓ respuesta con token
beclaims
   ↓ Authorization: Bearer <token>   ← texto plano en cada operación
```

#### Source

Configuración de la aplicación.

#### Sink

Tráfico HTTP saliente en claro.

#### Escenario de explotación

Un observador en cualquier tramo de la ruta interna —el propio VPC, el Transit Gateway, el Firewall Sur, GSNET o el segmento de Navarrete— captura en claro el usuario y la contraseña de la integración y, después, los tokens y el contenido de los reclamos: nombre, tipo y número de documento, correo, teléfono y el PDF adjunto (`ComplaintBook.pdfBase64`).

El atacante debe estar posicionado dentro de la red corporativa, lo que eleva el listón respecto a un escenario en Internet, pero es exactamente el escenario que la defensa en profundidad debe cubrir: un compromiso de cualquier workload con visibilidad de red en esa ruta convierte esto en una captura pasiva de credenciales.

#### Impacto

* **Confidencialidad:** credenciales de integración y datos personales de reclamantes expuestos en la red interna del grupo.
* **Integridad:** un atacante en ruta puede alterar el contenido del reclamo o su resultado; no hay ninguna protección de integridad en el canal.
* **Cumplimiento:** transmisión de datos personales sin cifrado, contraria a la política de cifrado en tránsito.

> Este hallazgo es coherente con el waiver de seguridad ya registrado para la API Contáctanos (endpoint UAT alojado en segmento productivo, con plan de migración). El presente informe documenta su manifestación en el código y aporta un control compensatorio implementable desde la aplicación (validación de esquema en el arranque) mientras la migración se completa.

#### Remediación

1. Migrar el proveedor a HTTPS con nombre DNS y certificado válido. Es un cambio de infraestructura, pero el código debe **impedir** que se opere en claro:

```java
// Código recomendado — rechazar en el arranque cualquier baseUrl no cifrada
@Bean
public WebClient tokenWebClient(ApiProperties apiProperties) throws SSLException {
    URI base = URI.create(apiProperties.getBaseUrl());
    if (!"https".equalsIgnoreCase(base.getScheme())) {
        throw new IllegalStateException(
            "api.contactanos.baseUrl debe usar https; valor recibido: " + base.getScheme());
    }
    ...
}
```

2. Eliminar el valor por defecto en claro (coincide con SEC-003):

```yaml
# Vulnerable
baseUrl: ${CONTACTANOS_BASE_URL:http://180.194.16.235/api_new}

# Recomendado
baseUrl: ${CONTACTANOS_BASE_URL}
```

3. Rotar las credenciales de Contáctanos: han circulado en claro y además están versionadas.
4. Mientras la migración no esté completa, exigir un túnel cifrado (mTLS a nivel de malla o VPN de sitio) y documentar el riesgo residual con fecha de cierre.

---

### SEC-010 — Fail-open: la API devuelve datos ficticios cuando falla el registro del reclamo

**Severidad:** Critical · **Confianza:** CONFIRMADO · **Prioridad:** P0
**CWE:** CWE-754 (Improper Check for Unusual or Exceptional Conditions), CWE-393 (Return of Wrong Status Code)
**OWASP:** API8:2023 Security Misconfiguration
**Proyecto/API:** cpe-nxhbsc-beclaims

#### Ubicación

```text
Archivo: cpe-nxhbsc-beclaims/src/main/java/.../infrastructure/adapters/output/client/ClaimsAdapter.java
Metodos: createClaims   · lineas 52-74
         getClaims      · lineas 82-103
         getReasons     · lineas 111-138
         getSubReason   · lineas 146-175
```

#### Descripción

Las cuatro operaciones capturan **cualquier** error del proveedor y lo sustituyen por una respuesta fabricada, devolviendo `200 OK`:

```java
// ClaimsAdapter.java:52-74
@Override
public ClaimsCreateResult createClaims(ClaimsCreate claimsCreate) {
    var request = mapper.toClaimsCreateDto(claimsCreate);

    return webClient.post()
            .uri(Constant.POST_CREATE_CLAIMS)
            .bodyValue(request)
            .retrieve()
            .onStatus(HttpStatusCode::is4xxClientError, ClaimsAdapter::handle4xxError)
            .onStatus(HttpStatusCode::is5xxServerError, ClaimsAdapter::handle5xxError)
            .bodyToMono(ClaimsCreateResultDTO.class)
            .onErrorResume((ex -> Mono.just(getMockCreateClaims(ex))))   // <-- fail-open
            .subscribeOn(Schedulers.boundedElastic())
            .map(mapper::toClaimsCreateResult)
            .block();
}

private static ClaimsCreateResultDTO getMockCreateClaims(Throwable ex) {
    log.warn("Error invoke method create claims: {}, then return getMockCreate", ex.getMessage());
    return ClaimsCreateResultDTO.builder()
            .complaintBookId("56782902")        // <-- identificador fijo, inventado
            .build();
}
```

`onErrorResume` se aplica **después** de los manejadores de 4xx y 5xx, por lo que atrapa precisamente las excepciones que estos generan (`ClaimsValidationException`, `ClaimsUnauthorizedException`, `ClaimsNotFoundException`, `ExternalServiceException`), además de timeouts y errores de conexión.

El resultado: si Contáctanos rechaza las credenciales (401), está caído (5xx), o la red falla, **el consumidor recibe `200 OK` con un número de reclamo que no existe**. El reclamo no se registró en ninguna parte.

`getClaims` va más allá y devuelve datos de una persona ficticia:

```java
// ClaimsAdapter.java:95-103
private static ClaimsResultDTO getMockClaimsResultDTO() {
    return ClaimsResultDTO.builder()
            .complaintBookId(Constant.COMPLAINT_BOOK_ID)
            .claimNumber("REC-2026-000084")
            .documentType(Constant.DOCUMENT_TYPE)
            .documentTypeDescription("DNI")
            .documentNumber("12345678")
            .build();
}
```

Un usuario consultando su reclamo recibiría el DNI y el número de expediente de otra persona (ficticia), presentados como reales.

#### Flujo

```text
POST /v1/claims_book/claims
   ↓
ClaimsApiDelegateImpl.create()
   ↓
ClaimsUseCase → ClaimsAdapter.createClaims()
   ↓
WebClient → Contáctanos  →  401 / 500 / timeout
   ↓
onErrorResume → getMockCreateClaims()
   ↓
200 OK  {"complaintBookId": "56782902"}     ← el reclamo NO existe
```

#### Source

Cualquier condición de error del proveedor: credenciales inválidas (probable, dadas SEC-003 y SEC-033), indisponibilidad, o timeout de 5 s con `CONTACTANOS_TIMEOUT:5000`.

#### Sink

Respuesta HTTP 200 al consumidor con datos fabricados.

#### Escenario de explotación

No requiere atacante: basta con que el proveedor falle. Pero es **provocable**: dado que no hay rate limiting (SEC-019) y el timeout es de 5 s, saturar el proveedor con peticiones concurrentes fuerza timeouts y, con ellos, que todos los reclamos legítimos de esa ventana se pierdan silenciosamente devolviendo confirmaciones falsas. Un atacante interesado en suprimir reclamos de clientes puede hacerlo sin dejar rastro visible para el usuario.

#### Impacto

* **Integridad:** pérdida silenciosa de registros. El sistema afirma haber hecho algo que no hizo.
* **Negocio y cumplimiento:** el Libro de Reclamaciones es una obligación regulatoria en Perú (INDECOPI). Emitir un número de reclamo inexistente supone incumplimiento formal y priva al cliente de constancia de su reclamo, con exposición a sanción y a litigio.
* **Confidencialidad:** menor, pero `getClaims` devuelve datos de un tercero (ficticio) como si fueran del solicitante.

#### Remediación

Eliminar los mocks del código productivo. Un fallo del proveedor debe propagarse como error.

```java
// Código vulnerable
.bodyToMono(ClaimsCreateResultDTO.class)
.onErrorResume((ex -> Mono.just(getMockCreateClaims(ex))))
.subscribeOn(Schedulers.boundedElastic())
.map(mapper::toClaimsCreateResult)
.block();
```

```java
// Código recomendado
.bodyToMono(ClaimsCreateResultDTO.class)
.subscribeOn(Schedulers.boundedElastic())
.map(mapper::toClaimsCreateResult)
.onErrorMap(ex -> !(ex instanceof BusinessException),
            ex -> {
                log.error("Fallo al registrar el reclamo en Contáctanos", ex);
                return new BusinessException(HttpStatus.SERVICE_UNAVAILABLE,
                                             List.of(Exceptions.TL9998));   // 503 explícito
            })
.block();
```

Complementariamente:

1. **Si se necesita tolerancia a fallos**, no fabricar datos: implementar un patrón *store-and-forward* — persistir el reclamo en una tabla de pendientes con estado `PENDIENTE_ENVIO`, devolver `202 Accepted` con un identificador propio del banco, y reintentar de forma asíncrona. El cliente obtiene constancia real y el reclamo no se pierde.
2. **Si los mocks existen para pruebas locales**, aislarlos con `@Profile("local")` o mediante un stub (WireMock) en los tests, nunca en el adaptador productivo.
3. Añadir al contrato el código de error correspondiente (`503`) y documentarlo, como ya se hace con `TL0001`.
4. Revisar `getReasons` y `getSubReason`: devolver catálogos inventados (`"Autenticacion del cliente"`, `"Interés"`, `"Comisiones"`) hace que el usuario clasifique su reclamo con motivos que el sistema destino no reconoce.

---

### SEC-011 — Contenido completo del documento en base64 escrito en el log

**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-532, CWE-359 · **OWASP:** API8:2023
**Proyecto/API:** cpe-nxhbsc-bedigitsignature

#### Ubicación

```text
Archivo: cpe-nxhbsc-bedigitsignature/src/main/java/.../infrastructure/adapters/output/client/DocumentClient.java
Metodo:  downloadAsBase64(Resource)   · lineas 76-85
Linea:   80
```

#### Descripción

```java
private Mono<String> downloadAsBase64(Resource file) {
    try{
        byte[] bites = file.getInputStream().readAllBytes();
        String base64 = Base64.getEncoder().encodeToString(bites);
        log.info("archivo en base64: {}", base64);       // <-- documento completo al log
        return Mono.just(base64);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}
```

Cada documento descargado desde `bedocmanagement` —contratos, formularios, documentos de identidad— se escribe íntegro en el log en nivel `INFO`. Además, `log.info("antes en obtener document, documentId: {}", documentId)` (línea 36) registra el identificador, lo que permite correlacionar contenido con documento.

El servicio no impone límite de tamaño (`fileWebClient` admite hasta 20 MB en memoria, `WebClientConfig:69-75`), por lo que cada línea de log puede alcanzar ~27 MB de base64.

#### Flujo

```text
POST /v1/signature/signer (sin auth)
   ↓
DocumentProcessService.processDocument() → DocumentClient.getDocument(documentId)
   ↓
POST bedocmanagement /v2/document_management/download_document_intern
   ↓
downloadAsBase64() → log.info("archivo en base64: {}", base64)
   ↓
Agregador de logs
```

#### Source

`documentId` del cuerpo de la petición, no autenticada.

#### Sink

Log de aplicación.

#### Escenario de explotación

Combinado con SEC-001 y SEC-002, un atacante solicita la firma de identificadores de documento arbitrarios; aunque la operación termine en error, el contenido de cada documento ya ha quedado volcado al log, desde donde puede extraerse sin acceso a S3 ni a la API de documentos. Es una vía de exfiltración indirecta que evita los controles de acceso del bucket.

En paralelo, un atacante puede saturar el almacenamiento de logs enviando lotes de documentos grandes (SEC-020).

#### Impacto

* **Confidencialidad:** documentos contractuales y de identidad accesibles desde el sistema de logs.
* **Disponibilidad y coste:** volumen de logs desproporcionado; posible pérdida de trazas por rotación acelerada y coste de ingesta.

#### Remediación

```java
// Código vulnerable
String base64 = Base64.getEncoder().encodeToString(bites);
log.info("archivo en base64: {}", base64);

// Código recomendado
String base64 = Base64.getEncoder().encodeToString(bites);
log.debug("Documento descargado. documentId={}, bytes={}", documentId, bites.length);
```

Y sustituir el `catch` que envuelve en `RuntimeException` por una excepción de dominio (ver SEC-028):

```java
// Código recomendado
} catch (IOException e) {
    throw new BusinessException(HttpStatus.BAD_GATEWAY, List.of(Exceptions.TL9999));
}
```

Añadir además un límite de tamaño explícito antes de leer el flujo completo, para no depender solo de `maxInMemorySize`.

---

### SEC-012 — Tokens biométricos y datos del documento de identidad escritos en el log

> ### 🟢 Estado en v1.6 (re-verificado 2026-09-03) — **ATENUADO · High → Medium**
>
> Este hallazgo estaba **sobredimensionado** en las versiones anteriores y esta revisión lo corrige. `FacephiAdapter` contiene hoy catorce llamadas del tipo `log.warn("request …: {}", request)`, y a primera vista parecen catorce vuelcos de datos biométricos. No lo son.
>
> Se ha comprobado **DTO a DTO**: de los 28 DTO de FacePhi, **26 declaran solo `@Getter @Setter @Builder`** y ninguno `@Data` ni `@ToString`. Sin `toString()` generado, `log.warn("{}", request)` imprime `FacephiAuthenticateFacialRequest@3f1a2b`: la identidad del objeto, no su contenido. Los campos `image`, `templateRaw`, `imageBuffer`, `token1`, `token2` y `bestImageToken` **no llegan al log**.
>
> Solo dos DTO tienen `toString()` generado:
>
> | DTO | Anotación | ¿Se registra? |
> | --- | --------- | ------------- |
> | `FacephiExtractDocumentDataRequest` | `@Data` | **Sí** — `FacephiAdapter:130` |
> | `FacephiIdentityRequest` | `@ToString` | No — `postIdentityResult` no registra el request |
>
> Queda por tanto **un único punto real de fuga**:
>
> ```java
> // FacephiAdapter.java:129-130
> var request = mapper.toFacephiExtractDocumentDataRequest(extractDocumentData);
> log.warn("request postExtractDocumentDataResult: {}", request.toString());   // @Data -> vuelca tokenOcr
> ```
>
> Lo que se filtra es el **`tokenOcr`**: el testigo de sesión con el que FacePhi referencia los datos extraídos del documento de identidad. No es el DNI ni la imagen, pero es la llave para recuperarlos del proveedor mientras la sesión siga viva, de modo que el hallazgo sigue siendo real — con un alcance mucho menor del reportado.
>
> **Cuidado con el motivo de la atenuación.** No es una corrección del equipo: es una verificación más precisa por nuestra parte. El día que alguien añada `@Data` a cualquiera de esos 26 DTO — un cambio de una línea que ninguna revisión marcaría como de seguridad — los catorce puntos de log pasan a volcar plantillas faciales. Por eso la remediación recomendada sigue siendo eliminar los `log.warn(request)`, no confiar en la ausencia de la anotación.
>
> Ver también **SEC-059**: lo que sí persiste, y con más recorrido, es la copia del request y del response en la tabla de auditoría de DynamoDB.

**Severidad:** ~~High~~ **Medium** · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-532, CWE-359 · **OWASP:** API8:2023
**Proyecto/API:** cpe-nxhbsc-beidentbiometric

#### Ubicación

```text
Archivo: cpe-nxhbsc-beidentbiometric/src/main/java/.../infrastructure/adapters/output/client/rest/FacephiAdapter.java
Lineas:  84   · log.info("request postIdentityResult: {}", request.toString())
         124  · log.warn("request postExtractDocumentDataResult: {}", request.toString())
DTOs:    FacephiIdentityRequest.java:10-21        (@ToString)
         FacephiExtractDocumentDataRequest.java   (@ToString)
```

#### Descripción

`FacephiAdapter` registra el request antes de cada llamada. La mayoría de esos DTO no declaran `@ToString`, por lo que `{}` imprime solo la referencia del objeto — sin fuga, aunque el log resulte inútil. **Dos sí lo declaran**, y son precisamente los que transportan datos biométricos y del documento de identidad:

```java
// FacephiIdentityRequest.java:10-21
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
@ToString                        // <-- imprime todos los campos
public class FacephiIdentityRequest {
  private String token1;         // token biométrico
  private String bestImageToken; // imagen facial seleccionada
  private String method;
  private Tracking tracking;
}
```

```java
// FacephiAdapter.java:82-84
public WrapperExecution<IdentityResult> postIdentityResult(Identity identity) {
    var request = mapper.toFacephiIdentityRequest(identity);
    log.info("request postIdentityResult: {}", request.toString());
```

Lo mismo ocurre en la línea 124 con `FacephiExtractDocumentDataRequest`, cuyo campo `tokenOcr` contiene los datos extraídos del DNI.

Es un contraste llamativo con el control implementado aguas abajo: antes de persistir en DynamoDB, `BiometricInputPort.cleanData()` **sí** trunca los campos largos:

```java
// BiometricInputPort.java:451-457
if (value instanceof String str) {
  if (str.length() > MAX_STRING_LENGTH) {      // 500
    // TODO guardar en S3
    return "[Content removed]";
  }
  return str;
}
```

La sanitización protege la base de datos pero **no se aplica al log**, que recibe el objeto sin filtrar.

#### Flujo

```text
POST /v1/identity_biometric/onboarding/identity   (sin auth)
   ↓
OnBoardingApiDelegateImpl.identity()
   ↓
BiometricInputPort.postIdentityResult()
   ↓
FacephiAdapter.postIdentityResult()
   ↓  log.info("request postIdentityResult: {}", request.toString())   ← token1 + bestImageToken
   ↓
FacePhi
   ↓
BiometricInputPort → cleanData() → DynamoDB  ← aquí sí se trunca
```

#### Source

Cuerpo de la petición de onboarding (imagen facial y datos de DNI aportados por el consumidor).

#### Sink

Log de aplicación.

#### Impacto

* **Confidencialidad:** datos biométricos —categoría especial de dato personal, no revocable— accesibles desde el sistema de logs, fuera del control de la tabla que sí los sanea.
* **Cumplimiento:** tratamiento de datos biométricos fuera del sistema autorizado para ello.

#### Remediación

```java
// Código vulnerable
log.info("request postIdentityResult: {}", request.toString());

// Código recomendado
log.debug("Invocando FacePhi identity. trackingId={}, method={}",
          request.getTracking() != null ? request.getTracking().getId() : null,
          request.getMethod());
```

```java
// FacephiIdentityRequest.java — recomendado
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
@ToString
public class FacephiIdentityRequest {
  @ToString.Exclude private String token1;
  @ToString.Exclude private String bestImageToken;
  private String method;
  private Tracking tracking;
}
```

Aplicar `@ToString.Exclude` de forma sistemática a `token1`, `token2`, `image`, `tokenOcr`, `oldRegisteredTemplateRaw` y `newRegisteredTemplateRaw` en todos los DTO de `client/dto/**`, y eliminar los `log.warn("request …: {}", request)` restantes, que no aportan información útil y solo generan ruido.

Resolver además el `// TODO guardar en S3` de `cleanData`: hoy el contenido truncado se pierde, lo que puede afectar a la trazabilidad exigida en un proceso de onboarding.

---

### SEC-013 — `wiretap(true)`: el tráfico HTTP completo, incluidas las cabeceras de autenticación, se vuelca al log

**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-532 · **OWASP:** API8:2023
**Proyecto/API:** beclaims, becreditrisk, becustombeprogrm, bedigitsignature, beidentbiometric, bewatchscreening

#### Ubicación

```text
beclaims          · WebClientConfig.java:65
becreditrisk      · WebClientConfig.java:84
becustombeprogrm  · WebClientConfig.java:33
bedigitsignature  · WebClientConfig.java:89
beidentbiometric  · WebClientConfig.java:64
bewatchscreening  · WebClientConfig.java:64
```

#### Descripción

Los seis servicios activan el *wiretap* de Reactor Netty en la construcción del `HttpClient`:

```java
// beidentbiometric/WebClientConfig.java:56-64
return HttpClient.create()
    .proxy(proxy -> proxy.type(ProxyProvider.Proxy.HTTP)
                         .host(proxyProperties.getHost())
                         .port(Integer.parseInt(proxyProperties.getPort())))
    .secure(t -> t.sslContext(sslContext).handlerConfigurator((SslHandler sslHandler) -> {}))
    .wiretap(true)                                   // <-- volcado completo
```

`wiretap(true)` instala un `LoggingHandler` en la categoría `reactor.netty.http.client.HttpClient` que registra **cabeceras y cuerpo** de peticiones y respuestas. Con esta forma de la sobrecarga, el formato por defecto incluye un volcado hexadecimal del contenido.

Lo que atraviesa esos clientes: `Authorization: Bearer <token>` (inyectado por el `ExchangeFilterFunction` de `beclaims` y `becustombeprogrm`), `x-api-key` de FacePhi y Zytrust, `Ocp-Apim-Subscription-Key` de SKY, el `client_secret` de Modelica en el formulario de token, credenciales de Gesintel y Contáctanos, y los cuerpos con datos biométricos y documentales.

**Consideración sobre explotabilidad:** el volcado solo se materializa si la categoría `reactor.netty.http.client.HttpClient` está en `DEBUG`. La configuración actual establece `logging.level.root: WARN`, por lo que en el estado presente **no se emite**. El riesgo es que la activación depende de un cambio de una línea de configuración —habitual durante una incidencia— que convierte instantáneamente el log en un repositorio de credenciales. Es un riesgo latente con probabilidad de materialización elevada, y por eso se clasifica como High y no como Medium.

#### Flujo

```text
Microservicio → HttpClient(wiretap=true) → proveedor externo
                      ↓ (si categoría en DEBUG)
              LoggingHandler → cabeceras + cuerpo → stdout → agregador de logs
```

#### Impacto

* **Confidencialidad:** exposición de todas las credenciales de integración y de los datos en tránsito, en el momento en que se eleve el nivel de log.
* **Operativo:** volumen de logs inmanejable y degradación de rendimiento si se activa en producción.

#### Remediación

```java
// Código vulnerable
.wiretap(true)
```

```java
// Código recomendado — desactivado por defecto, y nunca con volcado de cuerpo
@Bean
public HttpClient httpClient(HttpClientProperties props) throws SSLException {
    HttpClient client = HttpClient.create()
            .secure(spec -> spec.sslContext(sslContext))
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, props.connectTimeoutMs())
            .responseTimeout(Duration.ofMillis(props.responseTimeoutMs()));

    if (props.wiretapEnabled()) {          // false en todos los perfiles salvo local
        client = client.wiretap("reactor.netty.http.client.HttpClient",
                                LogLevel.DEBUG, AdvancedByteBufFormat.SIMPLE);  // sin cuerpo
    }
    return client;
}
```

Complementariamente, fijar de forma explícita el nivel de la categoría para que no pueda elevarse por un cambio global:

```yaml
logging.level:
  reactor.netty.http.client.HttpClient: WARN
```

y restringir el acceso al endpoint `/actuator/loggers` (hoy `permitAll`, SEC-022), que permite elevar el nivel de log en caliente sin autenticación — lo que convierte este hallazgo en explotable de forma remota mientras SEC-022 no se corrija.

---

### SEC-014 — `GET /documents/{document_id}/versions` ignora el identificador y devuelve la tabla completa

> ### ✅ Estado en v1.6 (re-verificado 2026-09-03) — **RESUELTO**
>
> `getDocumentVersion` ya no llama a `findAll()`. El código actual es, literalmente, el que este informe recomendaba:
>
> ```java
> // DocumentManagementAdapter.java:188-192  — CORREGIDO
> @Override
> public List<WrapperMySearchDocumentVersionResponse> getDocumentVersion(String id) {
>   var entities = repository.queryByPartitionKey(id);
>   return mapper.getVersions(entities);
> }
> ```
>
> `BaseDynamoRepository.queryByPartitionKey` (líneas 94-98) ejecuta una `Query` acotada por partition key en lugar de un `Scan` de tabla completa. El endpoint deja de devolver los documentos de otros clientes y deja de ser un vector de consumo asimétrico.
>
> **Lo que queda pendiente, y por qué no es este hallazgo:**
>
> * `findAll()` **sigue existiendo** en `BaseDynamoRepository:64-70`, aunque ya no se invoque desde ninguna ruta productiva. La recomendación de eliminarlo sigue vigente.
> * El endpoint sigue **sin verificar titularidad**: cualquiera con un token válido puede pedir las versiones de un `document_id` ajeno. Eso no es un defecto de este hallazgo sino de **SEC-002**, que sigue abierto.
> * No hay prueba de regresión que falle si alguien vuelve a cambiar `queryByPartitionKey` por `findAll`. Por el criterio de §20 esto debería dejarlo en `EN REVISIÓN`; se cierra porque la verificación sobre código se ha hecho aquí, pero **la prueba es lo que impide que vuelva como regresión**.
>
> Se conserva el detalle completo a continuación como registro histórico y como referencia del patrón correcto, reutilizable en SEC-039.

**Severidad (original):** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-200, CWE-405 (Asymmetric Resource Consumption)
**OWASP:** API1:2023 BOLA · API3:2023
**Proyecto/API:** cpe-nxhbsc-bedocmanagement

#### Ubicación

```text
Archivo: cpe-nxhbsc-bedocmanagement/src/main/java/.../infrastructure/adapters/output/DocumentManagementAdapter.java
Metodo:  getDocumentVersion(String id)   · lineas 187-190
Archivo: .../infrastructure/config/BaseDynamoRepository.java
Metodo:  findAll()                       · lineas 64-70
Archivo: .../infrastructure/adapters/output/DocumentMapper.java:121-131
```

#### Descripción

```java
// DocumentManagementAdapter.java:187-190
@Override
public List<WrapperMySearchDocumentVersionResponse> getDocumentVersion(String id) {
  var objectMetadataOptional = repository.findAll();      // <-- el parámetro 'id' no se usa
  return mapper.getVersions(objectMetadataOptional);
}
```

```java
// BaseDynamoRepository.java:64-70
public List<T> findAll() {
    List<T> results = new ArrayList<>();
    table.scan(ScanEnhancedRequest.builder().build())      // Scan completo, sin filtro ni paginación
            .items()
            .forEach(results::add);
    return results;
}
```

El parámetro `id` se recibe y se descarta. La operación ejecuta un `Scan` sin filtro sobre toda la tabla de documentos y devuelve una entrada por cada registro:

```java
// DocumentMapper.java:121-131
return entity.stream().map(enty ->{
    WrapperMySearchDocumentVersionResponse response = new WrapperMySearchDocumentVersionResponse();
    response.setVersionCode(enty.getVersion()+"");
    response.setVersionDescription(enty.getFileName());     // <-- nombre de archivo de TODOS
    return response;
}).collect(Collectors.toList());
```

El campo `versionDescription` expone el **nombre de fichero** de cada documento almacenado. Los nombres de documentos bancarios son habitualmente descriptivos (tipo de contrato, DNI del titular, fecha), por lo que el listado revela la estructura completa del repositorio documental.

#### Flujo

```text
GET /v2/document_management/documents/cualquier-valor/versions   (sin auth)
   ↓
DocumentManagementApiDelegateImpl.searchDocumentVersions(documentId)
   ↓
DocumentManagementUseCase.getDocumentVersion(id)   ← id descartado
   ↓
BaseDynamoRepository.findAll() → Scan completo de la tabla
   ↓
200 OK con el nombre de archivo de todos los documentos del sistema
```

#### Source

Cualquier valor en `{document_id}` — de hecho, ninguno: el resultado es independiente del parámetro.

#### Sink

Respuesta HTTP y `Scan` completo de DynamoDB.

#### Escenario de explotación

Una única petición sin autenticación enumera el repositorio documental completo. El atacante obtiene los nombres de todos los ficheros y, con ellos, información sobre qué clientes tienen qué contratos. Repetir la llamada consume capacidad de lectura de DynamoDB de forma desproporcionada (un `Scan` completo por petición), lo que constituye además un vector de denegación de servicio y de coste.

#### Impacto

* **Confidencialidad:** enumeración completa del repositorio documental.
* **Disponibilidad y coste:** consumo de RCU desproporcionado; con peticiones concurrentes, agotamiento de la capacidad provisionada de la tabla y degradación de todas las operaciones que dependen de ella.

#### Remediación

```java
// Código vulnerable
public List<WrapperMySearchDocumentVersionResponse> getDocumentVersion(String id) {
  var objectMetadataOptional = repository.findAll();
  return mapper.getVersions(objectMetadataOptional);
}
```

```java
// Código recomendado — consulta por partition key, con autorización previa
@Override
public List<WrapperMySearchDocumentVersionResponse> getDocumentVersion(String documentId) {
  authorizationService.assertCanAccessDocument(currentPrincipal(), documentId);   // ver SEC-002

  List<FileEntity> versions = repository.queryByPartitionKey(documentId);
  if (versions.isEmpty()) {
      throw new NotFoundException("documento_no_encontrado",
                                  "No se encontró el documento solicitado");
  }
  return mapper.getVersions(versions);
}
```

```java
// BaseDynamoRepository — recomendado: consulta acotada en lugar de scan
public List<T> queryByPartitionKey(String partitionKeyValue) {
    return table.query(QueryConditional.keyEqualTo(
                    Key.builder().partitionValue(partitionKeyValue).build()))
            .items()
            .stream()
            .toList();
}
```

Adicionalmente: **eliminar `findAll()` del repositorio base**. Un método que escanea una tabla completa sin límite no debería existir en el árbol productivo; si se necesita para tareas administrativas, debe vivir en un proceso batch con paginación explícita (`Limit` + `LastEvaluatedKey`). Lo mismo aplica a `search()` (SEC-039).

---

### SEC-015 — Clave de objeto S3 y `Content-Type` construidos con datos del cliente sin sanear

**Severidad:** High · **Confianza:** ALTA CONFIANZA · **Prioridad:** P1
**CWE:** CWE-99 (Improper Control of Resource Identifier), CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-639
**OWASP:** API3:2023 · API1:2023 · **Proyecto/API:** cpe-nxhbsc-bedocmanagement

#### Ubicación

```text
Archivo: .../infrastructure/adapters/output/DocumentManagementAdapter.java
Metodos: uploadDocument(...)                        · lineas 104-144
         validateRequestAndGetFolderReference(...)  · lineas 146-168
Archivo: .../application/validators/UploadDocumentValidator.java:11-26
```

#### Descripción

La clave del objeto en S3 se compone concatenando dos valores que llegan en el cuerpo de la petición:

```java
// DocumentManagementAdapter.java:146-168
private String validateRequestAndGetFolderReference(WrapperPostDocumentsRequest criteria, String id, String typeData) {
    ...
    String dni;
    List<WrapperMySearchDocumentResponseOwnersInner> name = doc.getOwners();
    if (name == null || name.isEmpty()) {
      dni = "";
    } else {
      dni = name.get(0).getOwnerId()+"/";        // <-- ownerId del request, sin validar
    }
    if(typeData == null || typeData.isEmpty()){
      return dni+doc.getName();                  // <-- name del request, sin sanear
    }
    return dni+id+typeData;
}
```

```java
// DocumentManagementAdapter.java:120-129
String userFolder = validateRequestAndGetFolderReference(criteria,documentId,typeData);
String key = PREFIJO_KEY+userFolder;

PutObjectRequest request = PutObjectRequest.builder()
        .bucket(bucketName)
        .key(key)
        .contentType(document.getMimeType())      // <-- MIME declarado por el cliente
        .build();

s3Client.putObject(request, RequestBody.fromBytes(fileBytes));
```

Tres problemas concurrentes:

1. **`ownerId` no se valida contra ningún titular.** El solicitante decide en qué carpeta de cliente se deposita el documento. Combinado con SEC-002, permite colocar documentos en el espacio de cualquier cliente.
2. **`name` no se sanea.** Las claves de S3 admiten `/` y cualquier carácter, y **no se normalizan**: el solicitante puede inyectar segmentos de ruta y escribir en prefijos arbitrarios del bucket. Como `putObject` sobrescribe sin condición, repetir un `ownerId` + `name` existentes **reemplaza el documento original**. La entrada en DynamoDB sí usa `putIfAbsent`, pero el objeto en S3 ya ha sido sobrescrito antes de esa comprobación (línea 129 precede a la 135).
3. **El `Content-Type` almacenado lo fija el cliente.** Tika solo se invoca cuando `appId` es `"biometric"` (línea 117), y aun así solo para derivar la extensión, no para validar. Un documento con contenido HTML y `mimeType: text/html` se sirve como HTML ejecutable a través de la URL prefirmada que genera `downloadDocument` (líneas 218-235).

El `UploadDocumentValidator` solo comprueba que el contenido sea base64 decodificable; no valida `name`, `ownerId`, `mimeType` ni tamaño.

#### Flujo

```text
POST /v2/document_management/upload_document
{ "document": { "folderReference": "<base64>", "name": "…", "mimeType": "text/html",
                "owners": [ { "ownerId": "<DNI ajeno>" } ] } }
   ↓
UploadDocumentValidator.validate()        ← solo verifica que sea base64
   ↓
validateRequestAndGetFolderReference()    ← concatena ownerId + name
   ↓
s3Client.putObject(bucket, PREFIJO_KEY + ownerId + "/" + name, contentType=cliente)
   ↓
downloadDocument → URL prefirmada (10 min) → el navegador recibe el Content-Type declarado
```

#### Source

`document.owners[0].ownerId`, `document.name`, `document.mimeType` del cuerpo de la petición.

#### Sink

`PutObjectRequest.key()` y `.contentType()`, y posteriormente la URL prefirmada de descarga.

#### Escenario de explotación

* **Sobrescritura:** el atacante conoce o infiere el `ownerId` y el `name` de un documento existente (SEC-014 se los proporciona: `versionDescription` devuelve los nombres de archivo de todos los documentos) y sube contenido propio con esa misma clave, reemplazando el contrato original en S3.
* **Colocación arbitraria:** mediante `/` en `name`, deposita objetos en prefijos del bucket destinados a otros procesos.
* **XSS almacenado:** sube HTML con `mimeType: text/html`; cuando ese documento se descarga vía URL prefirmada, el navegador lo ejecuta en el origen de S3. Si alguna aplicación interna abre documentos en un `iframe` o pestaña, el script se ejecuta con acceso a lo que ese origen permita.

#### Impacto

* **Integridad:** sustitución de documentos contractuales — con impacto probatorio directo.
* **Confidencialidad:** ejecución de contenido activo servido desde el dominio de almacenamiento del banco.
* **Cumplimiento:** documentos depositados bajo el identificador de un titular que no los aportó.

#### Remediación

```java
// Código vulnerable
String dni = name.get(0).getOwnerId() + "/";
return dni + doc.getName();
...
.key(PREFIJO_KEY + userFolder)
.contentType(document.getMimeType())
```

```java
// Código recomendado
private static final Set<String> ALLOWED_MIME =
        Set.of("application/pdf", "image/jpeg", "image/png");
private static final Pattern SAFE_NAME = Pattern.compile("^[A-Za-z0-9._-]{1,120}$");

private String buildObjectKey(WrapperPostDocumentsRequest criteria, String documentId,
                              byte[] fileBytes) {

    String ownerId = Optional.ofNullable(criteria.getDocument().getOwners())
            .filter(o -> !o.isEmpty())
            .map(o -> o.get(0).getOwnerId())
            .orElseThrow(() -> new BadRequestException("owner_requerido", "ownerId es obligatorio"));

    authorizationService.assertCanWriteForOwner(currentPrincipal(), ownerId);   // ver SEC-002

    if (!SAFE_NAME.matcher(criteria.getDocument().getName()).matches()) {
        throw new BadRequestException("nombre_invalido",
                "El nombre del documento contiene caracteres no permitidos");
    }

    // el nombre del cliente NO forma parte de la clave: se guarda como metadato
    return PREFIJO_KEY + sha256Hex(ownerId) + "/" + documentId;
}

private String resolveContentType(byte[] fileBytes, String declared) {
    String detected = new Tika().detect(fileBytes);          // siempre, no solo para 'biometric'
    if (!ALLOWED_MIME.contains(detected)) {
        throw new BadRequestException("tipo_no_permitido",
                "Tipo de archivo no admitido: " + detected);
    }
    if (declared != null && !detected.equals(declared)) {
        log.warn("MIME declarado ({}) distinto del detectado ({}); se usa el detectado",
                 declared, detected);
    }
    return detected;                                          // se almacena el detectado
}
```

```java
// Subida: clave derivada, MIME detectado, cabecera de descarga forzada, y no sobrescribir
PutObjectRequest request = PutObjectRequest.builder()
        .bucket(bucketName)
        .key(buildObjectKey(criteria, documentId, fileBytes))
        .contentType(resolveContentType(fileBytes, document.getMimeType()))
        .contentDisposition("attachment")                      // evita render en el navegador
        .serverSideEncryption(ServerSideEncryption.AWS_KMS)    // KMS ya disponible en la plataforma
        .metadata(Map.of("owner-id", ownerId, "original-name", document.getName()))
        .build();
```

Complementariamente: usar el `documentId` (UUID ya generado en la línea 107) como parte inmutable de la clave, activar **versionado de objetos** en el bucket para que una sobrescritura no destruya el original, y aplicar cifrado con la clave KMS que la arquitectura ya provee.

---

### SEC-016 — Integraciones salientes sin timeout

> ### ⏸️ APLAZADO en v1.7 (2026-09-03) — fuera del alcance de este Ethical Hacking
>
> El único proyecto que quedaba con este defecto es `cpe-nxhbsc-becustombeprogrm`, que no entra en el EH. Los otros dos servicios ya lo habían corregido en v1.5.
>
> **El hallazgo sigue siendo válido y sigue abierto.** No se ha corregido nada: el código permanece desplegado y el defecto es explotable por quien tenga acceso a ese componente. Lo único que cambia es que **no se mide contra este ejercicio** y no cuenta en los 47 hallazgos de alcance — sí en los 56 de deuda técnica. Se conserva íntegro, con su evidencia y su remediación, para que al volver a alcance recupere su historial en lugar de reaparecer como hallazgo nuevo.

> ### 🟡 Estado en v1.5 (re-verificado 2026-08-31) — **ATENUADO · 3 → 1 proyecto**
>
> Dos de los tres se han corregido, cada uno con el idioma de su cliente HTTP:
>
> | Proyecto | Antes | Ahora |
> | -------- | ----- | ----- |
> | `beemailboxes` | Sin timeout | `RestTemplateConfig:53-56` — `setConnectionRequestTimeout(10s)` + `setResponseTimeout(10s)` |
> | `bedigitsignature` | Sin timeout | `WebClientConfig:90-99` — `CONNECT_TIMEOUT_MILLIS` + `responseTimeout` + `Read/WriteTimeoutHandler` |
> | **`becustombeprogrm`** | Sin timeout | **Sin timeout** |
>
> `becustombeprogrm/…/config/WebClientConfig.java:27-33` sigue devolviendo un `HttpClient.create()` con proxy, SSL y `wiretap`, y **ningún timeout**. Es precisamente el peor de los tres para dejarlo así, porque es el único que además reintenta: `SKYServiceAdapter:94` aplica `retryWhen(WebClientRetryPolicy.threeAttempts())` sobre esa conexión. Una llamada colgada a SKY consume el hilo indefinidamente y se reintenta tres veces (SEC-017).


**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-1088 (Synchronous Access of Remote Resource without Timeout), CWE-400
**OWASP:** API4:2023 Unrestricted Resource Consumption
**Proyecto/API:** becustombeprogrm, beemailboxes, bedigitsignature

#### Ubicación

```text
becustombeprogrm · WebClientConfig.java:20-34   · bean httpClient() compartido por SKY y Qurable
beemailboxes     · RestTemplateConfig.java:28-63 · bean restTemplate() compartido por OTP y correo
bedigitsignature · WebClientConfig.java:37-50   · documentWebClient
bedigitsignature · WebClientConfig.java:68-75   · fileWebClient
```

#### Descripción

Cuatro clientes HTTP se construyen sin ningún límite temporal:

```java
// becustombeprogrm/WebClientConfig.java:20-34
@Bean
public HttpClient httpClient() throws SSLException {
    SslContext sslContext = SslContextBuilder.forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            .build();

    return HttpClient.create()
            .proxy(proxy -> proxy.type(ProxyProvider.Proxy.HTTP)
                                 .host(proxyProperties.getHost())
                                 .port(Integer.parseInt(proxyProperties.getPort())))
            .secure(ssl -> ssl.sslContext(sslContext))
            .wiretap(true);
    // sin CONNECT_TIMEOUT_MILLIS, sin responseTimeout, sin Read/WriteTimeoutHandler
}
```

```java
// bedigitsignature/WebClientConfig.java:37-50
@Bean
public WebClient documentWebClient(WebClient.Builder builder, DocumentApiProperties properties) {
    return builder
            .baseUrl(properties.baseUrl())
            .defaultHeaders(headers -> { ... })
            .build();        // sin clientConnector: usa el HttpClient por defecto, sin timeouts
}
```

`beemailboxes` construye el `RestTemplate` con un `PoolingHttpClientConnectionManager` pero **no configura `RequestConfig`**, por lo que hereda los valores por defecto de Apache HttpClient 5 (sin límite de respuesta). Es especialmente crítico porque este cliente es el que habla con el proveedor de OTP y correo.

El agravante es la combinación con el modelo de ejecución: todos los adaptadores llaman a `.block()` sobre el `Mono`, ocupando un hilo del pool de Tomcat durante toda la espera. Un proveedor que acepte la conexión y no responda inmoviliza hilos indefinidamente hasta agotar el pool.

Contraste: `beclaims`, `becreditrisk`, `beidentbiometric` y `bewatchscreening` **sí** configuran `CONNECT_TIMEOUT_MILLIS`, `responseTimeout`, `ReadTimeoutHandler` y `WriteTimeoutHandler`. La práctica correcta existe en el código base; simplemente no se aplicó de forma consistente.

#### Flujo

```text
Petición entrante → hilo de Tomcat
   ↓
Adapter → WebClient/RestTemplate sin timeout → .block()
   ↓
Proveedor externo no responde
   ↓
Hilo bloqueado indefinidamente; se repite con cada petición
   ↓
Agotamiento del pool → el servicio deja de atender cualquier petición
```

#### Escenario de explotación

No requiere un atacante sofisticado: basta con que un proveedor se degrade. Pero es provocable — un atacante que consiga que el proveedor responda lentamente (o que ocupe su cuota, dado que no hay rate limiting, SEC-019) provoca la caída completa del microservicio. En `beemailboxes` esto significa que ni el OTP ni el correo funcionan; en `becustombeprogrm`, que el alta de clientes queda inoperante.

#### Impacto

* **Disponibilidad:** denegación de servicio completa del microservicio afectado, con propagación a cualquier servicio que dependa de él.
* **Operativo:** los pods pueden quedar vivos ante el *liveness probe* mientras son incapaces de atender tráfico.

#### Remediación

```java
// Código recomendado — becustombeprogrm
@Bean
public HttpClient httpClient(ProxyProperties proxyProperties, HttpClientProperties props) throws SSLException {
    return HttpClient.create()
            .proxy(p -> p.type(ProxyProvider.Proxy.HTTP)
                         .host(proxyProperties.getHost())
                         .port(Integer.parseInt(proxyProperties.getPort())))
            .secure(spec -> spec.sslContext(sslContext))           // ver SEC-004
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, props.connectTimeoutMs())   // p. ej. 3000
            .responseTimeout(Duration.ofMillis(props.responseTimeoutMs()))            // p. ej. 8000
            .doOnConnected(conn -> conn
                    .addHandlerLast(new ReadTimeoutHandler(props.readTimeoutMs(), TimeUnit.MILLISECONDS))
                    .addHandlerLast(new WriteTimeoutHandler(props.writeTimeoutMs(), TimeUnit.MILLISECONDS)));
}
```

```java
// Código recomendado — beemailboxes
RequestConfig requestConfig = RequestConfig.custom()
        .setConnectionRequestTimeout(Timeout.ofSeconds(2))
        .setResponseTimeout(Timeout.ofSeconds(8))
        .build();

CloseableHttpClient httpClient = HttpClients.custom()
        .setConnectionManager(connectionManager)
        .setDefaultRequestConfig(requestConfig)
        .setProxy(proxy)
        .build();
```

Además: aplicar `.timeout(Duration…)` en los `Mono` como red de seguridad, externalizar los valores por entorno, y revisar `bewatchscreening`, cuyo `GESINTEL_TIMEOUT` por defecto es de **500 ms** — el problema opuesto: un umbral tan bajo garantiza timeouts espurios contra un proveedor de AML que atraviesa Netskope.

---

### SEC-017 — Reintentos automáticos sobre operaciones no idempotentes

> ### ⏸️ APLAZADO en v1.7 (2026-09-03) — fuera del alcance de este Ethical Hacking
>
> Afecta solo a `cpe-nxhbsc-becustombeprogrm` (reintentos sobre el alta de usuario en SKY), que no entra en el EH.
>
> **El hallazgo sigue siendo válido y sigue abierto.** No se ha corregido nada: el código permanece desplegado y el defecto es explotable por quien tenga acceso a ese componente. Lo único que cambia es que **no se mide contra este ejercicio** y no cuenta en los 47 hallazgos de alcance — sí en los 56 de deuda técnica. Se conserva íntegro, con su evidencia y su remediación, para que al volver a alcance recupere su historial en lugar de reaparecer como hallazgo nuevo.

> ### 🟡 Estado en v1.6 (re-verificado 2026-09-03) — **ATENUADO · High → Medium**
>
> La política de reintentos se ha acotado. Antes reintentaba ante cualquier error; ahora filtra:
>
> ```java
> // WebClientRetryPolicy.java:21-27
> private static boolean isRetryable(Throwable throwable) {
>     if (throwable instanceof WebClientResponseException wcre) {
>         return wcre.getStatusCode().is5xxServerError();
>     }
>     return throwable instanceof java.io.IOException
>             || throwable instanceof java.util.concurrent.TimeoutException;
> }
> ```
>
> Excluir los 4xx es correcto y elimina la peor variante: ya no se reintenta un `409 Usuario ya registrado`, que era el caso que garantizaba el duplicado.
>
> **Por qué no se cierra.** Los dos casos que quedan — 5xx y `TimeoutException` — son precisamente aquellos en los que **no se sabe si la operación se ejecutó**. Un timeout no significa que SKY no diera de alta al usuario, solo que la confirmación no llegó; reintentar dos veces más sobre `POST /register_customer` sin clave de idempotencia sigue pudiendo producir tres altas del mismo cliente en el programa de beneficios. La remediación pendiente es la misma de siempre: una cabecera de idempotencia derivada del identificador de cliente, o comprobación previa de existencia.

**Severidad:** ~~High~~ **Medium** · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-837 (Improper Enforcement of a Single, Unique Action), CWE-799
**OWASP:** API4:2023 · **Proyecto/API:** cpe-nxhbsc-becustombeprogrm

#### Ubicación

```text
Archivo: .../infrastructure/adapters/output/external/SKYServiceAdapter.java
Metodo:  createUser(CreateUserRequest)   · lineas 49-102 (retry en linea 94)
Archivo: .../infrastructure/config/WebClientRetryPolicy.java:16-27
```

#### Descripción

```java
// SKYServiceAdapter.java:52-95
return webClient
        .post()
        .uri(Constant.URI_API_SKY)          // POST /v1/user  — alta de usuario
        ...
        .retryWhen(WebClientRetryPolicy.threeAttempts())     // <-- reintenta un POST de creación
        .block();
```

```java
// WebClientRetryPolicy.java:16-27
public static Retry threeAttempts() {
    return Retry.backoff(MAX_ATTEMPTS - 1, BACKOFF)     // 2 reintentos, 300 ms
            .filter(WebClientRetryPolicy::isRetryable);
}

private static boolean isRetryable(Throwable throwable) {
    if (throwable instanceof WebClientResponseException wcre) {
        return wcre.getStatusCode().is5xxServerError();
    }
    return throwable instanceof java.io.IOException
            || throwable instanceof java.util.concurrent.TimeoutException;
}
```

La política reintenta ante 5xx, `IOException` y `TimeoutException`. Esos tres casos comparten una propiedad esencial: **son ambiguos**. Un timeout o un corte de conexión no indican que la operación no se ejecutara — solo que no se recibió la confirmación. El proveedor puede haber creado el usuario y haber fallado al responder.

No existe clave de idempotencia en la petición: `CreateUserRequest` no incluye ningún identificador de transacción único que permita al proveedor detectar el duplicado. El único indicio de que el sistema ya sufre este problema está en el propio código: existe una tabla de "casos a regularizar" en DynamoDB (`AltaUsuarioService:117`, `log.info("Caso a regularizar registrado en DynamoDB…")`) para gestionar altas fallidas manualmente.

El problema se agrava porque este mismo cliente **no tiene timeout** (SEC-016): sin límite de respuesta, `TimeoutException` no llega a producirse por el cliente, pero sí `IOException` ante cortes de conexión, y cada uno dispara un reintento.

#### Flujo

```text
POST /v1/customer_benefit_programs/register_customer
   ↓
AltaUsuarioService → SKYServiceAdapter.createUser()
   ↓
POST SKY /v1/user  → el proveedor crea el usuario → la respuesta se pierde (timeout/reset)
   ↓
retryWhen → segundo POST → el proveedor responde 409 "usuario ya registrado"
   ↓
ExternalServiceException(TL0016)  → el cliente recibe un error pese a que el alta se realizó
```

o, si el proveedor no deduplica:

```text
   ↓  dos o tres altas del mismo cliente en SKY
```

#### Impacto

* **Integridad:** duplicación de altas en el programa de beneficios, o altas realizadas que se reportan como fallidas — ambos casos generan discrepancia entre los sistemas y trabajo manual de regularización.
* **Negocio:** un alta duplicada en un programa de puntos/beneficios tiene efecto económico directo.

#### Remediación

```java
// Código vulnerable
.retryWhen(WebClientRetryPolicy.threeAttempts())
```

Dos alternativas, en orden de preferencia:

**(a) Idempotencia real** — la correcta si el proveedor la soporta:

```java
// Código recomendado
String idempotencyKey = criteria.getIdempotencyKey();   // estable por operación de negocio,
                                                        // p. ej. UUID v5 sobre (documentNumber, programId)
return webClient
        .post()
        .uri(Constant.URI_API_SKY)
        .header("Idempotency-Key", idempotencyKey)
        .header("Ocp-Apim-Subscription-Key", SKY_SUBSCRIPTION_KEY)
        ...
        .retryWhen(WebClientRetryPolicy.threeAttempts())   // ahora sí es seguro reintentar
        .block();
```

**(b) Reintento restringido a fallos inequívocos** — si el proveedor no ofrece idempotencia:

```java
// WebClientRetryPolicy — recomendado
public static Retry threeAttemptsForReads() {           // solo para GET
    return Retry.backoff(MAX_ATTEMPTS - 1, BACKOFF).filter(WebClientRetryPolicy::isRetryable);
}

public static Retry connectOnlyForWrites() {            // para POST/PUT/PATCH
    return Retry.backoff(MAX_ATTEMPTS - 1, BACKOFF)
            .filter(t -> t instanceof ConnectException          // la petición nunca salió
                      || t instanceof ConnectTimeoutException);
}
```

Un `ConnectException` garantiza que la petición no llegó al proveedor; un `ReadTimeout` o un `reset` tras el envío, no. Solo el primero es seguro para una escritura.

Complementariamente: mantener el registro en la tabla de regularización, pero acompañarlo de un proceso de conciliación automática que consulte al proveedor por la clave de idempotencia antes de dar el alta por fallida.

---

### SEC-018 — El cuerpo del error del proveedor se propaga al consumidor

> ### 🟡 Estado en v1.6 (re-verificado 2026-09-03) — **ATENUADO · High → Medium**
>
> **Corregido en la integración con SKY**, que era la más expuesta. `SKYServiceAdapter` mapea ahora cada situación a un código corporativo y registra el detalle del proveedor **solo en el log interno**:
>
> ```java
> // SKYServiceAdapter.java:61-67  — patrón correcto, replicable
> if (status == 406) {
>     return clientResponse.bodyToMono(String.class).flatMap(body -> {
>         log.error("Error de desencriptado en SKY. detalle interno: {}", extractSkyErrorDetail(body));
>         return Mono.error(new ExternalServiceException(HttpStatus.CONFLICT, Exceptions.TL0015, null));
>     });
> }
> ```
>
> Lo mismo para 409 (`TL0016`), 400 (`TL0017`) y el resto de 4xx (`TL0018`). **Este es el patrón que el resto del conjunto debería copiar.**
>
> **La cadena (a) está verificada como cerrada.** Los cuatro puntos que construían la excepción pasan ahora `null` como `detail`:
>
> ```java
> return Mono.error(new ExternalServiceException(HttpStatus.CONFLICT, Exceptions.TL0015, null));
> //                                                                                     ↑ en v1.5: extractSkyErrorDetail(body)
> ```
>
> `ControllerAdvice:28-32` publica `externalServiceException.getDetail()`, que ahora es `null`. `extractSkyErrorDetail` sigue devolviendo el `rawBody` íntegro, pero su único consumidor es `log.error`: el dato ya no sale del pod.
>
> **Por qué no se cierra — la cadena (b) está intacta.** `bedigitsignature` no se tocó en esta entrega:
>
> ```java
> // Util.java:15-23  — SIN CAMBIOS respecto a v1.5
> return response -> response.bodyToMono(String.class)
>         .defaultIfEmpty("")
>         .flatMap(body -> Mono.error(new SantanderException(
>                 String.format("%s. Status=%s, body=%s", message, response.statusCode(), body))));
> ```
>
> ```java
> // DocumentProcessService.java:146-152  — SIN CAMBIOS
> errorDTO.setDescription(result);   // result = error.getMessage() → "… Status=…, body=…" del proveedor
> ```
>
> **Un tercer punto, que conviene no sobrevalorar.** `QurableServiceAdapter:61-63` lanza `new RuntimeException("error: " + body)` dentro del `onStatus`. Ese `RuntimeException` **no** es una `BusinessException`, así que el `ControllerAdvice` no lo captura: lo recoge el `catch (Exception ex)` del propio adaptador y lo re-envuelve en `SantanderException` con un **mensaje fijo**. El cuerpo del proveedor queda por tanto en el log y en la cadena de causas, y solo llegaría al consumidor si el framework Gluon serializa la causa en su envelope. **Confianza: REQUIERE VALIDACIÓN** — se resuelve inspeccionando una respuesta de error real, no leyendo el código. Con independencia de eso, componer el mensaje con el cuerpo del proveedor es una mala práctica que conviene eliminar.
>
> El patrón es el habitual: **la integración que se tocó se corrigió bien, y la que no se tocó sigue igual**. Replicar el patrón de SKY en `bedigitsignature` es mecánico.

**Severidad:** ~~High~~ **Medium** · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information), CWE-497
**OWASP:** API8:2023 · **Proyecto/API:** becustombeprogrm, bedigitsignature

#### Ubicación

```text
becustombeprogrm · SKYServiceAdapter.java:104-131  · extractSkyErrorDetail(String)
becustombeprogrm · ControllerAdvice.java:20-39     · description ← ExternalServiceException.getDetail()
bedigitsignature · Util.java:99-111                · handleError(String)
bedigitsignature · DocumentProcessService.java:124-129, 142-149 · error.getMessage() → ErrorDTO.description
```

#### Descripción

Dos cadenas independientes llevan el texto de error del proveedor hasta la respuesta del consumidor.

**(a) `becustombeprogrm` → SKY.** Cuando el cuerpo de error no encaja en la estructura esperada, se devuelve completo:

```java
// SKYServiceAdapter.java:104-131
private String extractSkyErrorDetail(String rawBody) {
    try {
        JsonNode root = objectMapper.readTree(rawBody);
        ...
        return !sb.isEmpty() ? sb.toString() : rawBody;      // <-- cuerpo íntegro del proveedor
    } catch (Exception ex) {
        log.warn("No se pudo parsear el body de error de SKY: {}", rawBody);
        return rawBody;                                       // <-- cuerpo íntegro del proveedor
    }
}
```

Ese valor viaja como `detail` de la excepción y el `ControllerAdvice` lo publica tal cual:

```java
// ControllerAdvice.java:28-32
item.setDescription(
        ex instanceof ExternalServiceException externalServiceException
                ? externalServiceException.getDetail()        // <-- al consumidor
                : violation.getDescription()
);
```

**(b) `bedigitsignature` → DMS/Zytrust.** El helper compone un mensaje que incluye estado y cuerpo:

```java
// Util.java:99-111
return response -> response.bodyToMono(String.class)
        .defaultIfEmpty("")
        .flatMap(body -> Mono.error(
                new SantanderException(
                        String.format("%s. Status=%s, body=%s", message,
                                      response.statusCode(), body))));
```

y ese mensaje acaba en la respuesta de negocio:

```java
// DocumentProcessService.java:124-129
.onErrorResume(error -> {
    log.error(error.getMessage());
    return Mono.just(buildUniqueResponse(error.getMessage(), documentId));   // <-- mensaje completo
});

// DocumentProcessService.java:142-149
if(Constant.ERROR.equals(applicationSignatureData.getEstado())){
    ErrorDTO errorDTO = new ErrorDTO();
    errorDTO.code("TL9999");
    errorDTO.setLevel("error");
    errorDTO.setMessage("Service unavailable");
    errorDTO.setDescription(result);          // <-- "…Status=…, body=…" del proveedor
    applicationSignatureData.setError(errorDTO);
}
```

Es una desviación del propio estándar del proyecto: el resto de servicios mapea correctamente a códigos `TL*` con descripciones controladas.

#### Flujo

```text
Consumidor → API → Proveedor (SKY / DMS / Zytrust)
                        ↓ 4xx con cuerpo de error propio
                   extractSkyErrorDetail / Util.handleError
                        ↓ texto íntegro
                   ErrorItem.description / ErrorDTO.description
                        ↓
                   Respuesta HTTP al consumidor
```

#### Source

Respuesta del proveedor externo — **no confiable**, y fuera del control del banco.

#### Sink

Cuerpo de la respuesta HTTP devuelta al consumidor.

#### Escenario de explotación

El atacante envía peticiones deliberadamente malformadas para provocar errores del proveedor y recolectar sus mensajes. Con ello obtiene: nombres de campos internos del proveedor, rutas y hostnames de su infraestructura, versiones de su stack, identificadores de correlación, y en ocasiones fragmentos de datos de otras peticiones. Es reconocimiento gratuito de una infraestructura de tercero, publicado por la API del banco.

Hay además un riesgo de segundo orden: el texto proviene del proveedor y se devuelve sin codificar. Si el consumidor lo renderiza en una interfaz sin escapar, el proveedor —o quien comprometa su respuesta, especialmente dado SEC-004— controla contenido que se ejecuta en el cliente.

#### Impacto

* **Confidencialidad:** divulgación de detalles internos de sistemas de terceros y, por transitividad, del acoplamiento del banco con ellos.
* **Integridad:** contenido no confiable propagado al consumidor sin neutralizar.
* **Acoplamiento:** el consumidor termina dependiendo de textos de error del proveedor que pueden cambiar sin aviso.

#### Remediación

```java
// Código vulnerable
return !sb.isEmpty() ? sb.toString() : rawBody;
...
errorDTO.setDescription(result);
```

```java
// Código recomendado — el detalle va al log con correlación; al consumidor, un código estable
private String handleSkyError(String rawBody, String correlationId) {
    log.error("Error de SKY. correlationId={}, body={}", correlationId, rawBody);   // solo al log
    return "Error al procesar la solicitud en el sistema de beneficios. " +
           "Referencia: " + correlationId;                                          // al consumidor
}
```

```java
// Código recomendado — bedigitsignature
.onErrorResume(error -> {
    String correlationId = UUID.randomUUID().toString();
    log.error("Fallo procesando documento {}. correlationId={}", documentId, correlationId, error);
    return Mono.just(buildErrorResponse(documentId, "TL9999",
            "Servicio no disponible. Referencia: " + correlationId));
});
```

Regla general: **el detalle técnico va al log con un identificador de correlación; al consumidor va el código `TL*` y ese identificador**. Así el soporte puede reconstruir el caso sin que el detalle salga del perímetro. Revisar en la misma línea `handle4xxError`/`handle5xxError` de `ClaimsAdapter` (líneas 178-201), que propagan `errorBody.getMessage()` del proveedor a la excepción de dominio.

---

### SEC-019 — Ausencia de limitación de peticiones y amplificación de recursos

> ### 🟡 Estado en v1.5 (re-verificado 2026-08-31) — **ATENUADO parcialmente · sigue High**
>
> Ha aparecido el primer control de caudal del conjunto: `beemailboxes` incorpora un `RateLimiterConfig` con Resilience4j (3 peticiones cada 15 minutos) aplicado en `EmailboxIdInputPort:53-67` al flujo de **generación** de OTP. Es un avance real sobre el vector de envío masivo de correo a un mismo destinatario.
>
> No cierra el hallazgo, por dos motivos distintos:
>
> * **Cobertura**: es el único de los once servicios que tiene alguno, y dentro de `beemailboxes` cubre una de las dos operaciones sensibles. Los vectores de agotamiento de recursos de `bedocmanagement` (SEC-014, SEC-039) y de amplificación de `bedigitsignature` siguen sin límite.
> * **Diseño**: el limitador tal como está implementado deja abierto el vector de fuerza bruta y añade uno nuevo de consumo de memoria. Eso se documenta aparte, en **SEC-053**.


**Severidad:** High · **Confianza:** ALTA CONFIANZA · **Prioridad:** P1
**CWE:** CWE-770 (Allocation of Resources Without Limits), CWE-799
**OWASP:** API4:2023 Unrestricted Resource Consumption · API6:2023 · **Proyecto/API:** todos

#### Descripción

No existe ningún mecanismo de limitación en el código: ni bucket de tokens, ni `@RateLimiter` de Resilience4j, ni contadores por consumidor, ni bulkhead, ni circuit breaker. La única búsqueda que devuelve resultados sobre resiliencia es `WebClientRetryPolicy` — que **añade** carga en lugar de contenerla (SEC-017).

El diagrama sitúa Imperva y el API Gateway delante, y ambos pueden aplicar cuotas. Eso mitiga el escenario volumétrico simple, y por ello el hallazgo no se clasifica como Critical. Pero hay dos efectos que ninguna cuota de borde resuelve:

**(a) Amplificación asimétrica.** Una única petición legítima genera un número de operaciones internas y externas que el solicitante controla:

```java
// bedigitsignature/DocumentProcessService.java:48-61
String loteId = UUID.randomUUID().toString();
return Flux.fromIterable(request.getDocumentos())        // <-- lista sin límite (SEC-020)
        .flatMap(document -> processDocument(document.getIdDocumento(), request, loteId),
                 MAX_CONCURRENCY)                        // 5 en paralelo
        .collectList()
        ...
```

Cada elemento de `documentos` desencadena una llamada a `bedocmanagement` (que descarga de S3) **y** una llamada al proveedor de firma. Con N documentos: `1 petición → 2N llamadas`, y el contrato **no limita N** (`ApplicationSignDocumentRequest` es un array sin `maxItems`). Una cuota de 10 peticiones por minuto en el gateway no impide que cada una de esas 10 genere miles de operaciones internas.

Lo mismo aplica a `becreditrisk`, donde una petición dispara cuatro consultas a RDS más una llamada a Modellica, y a `bedocmanagement`, donde `search_documents` ejecuta un `Scan` completo de DynamoDB (SEC-039).

**(b) Abuso funcional del envío de correo y OTP.** El endpoint `POST /{emailbox_id}/send_email` genera un OTP contra Celmedia y envía un correo al destinatario indicado en el cuerpo. Sin límite por destinatario ni por sujeto, permite: consumir la cuota contratada con Celmedia, usar la infraestructura de correo del banco para enviar mensajes con plantilla corporativa a direcciones arbitrarias, y saturar el buzón de una víctima concreta.

#### Impacto

* **Disponibilidad:** agotamiento de capacidad de DynamoDB, del pool de conexiones a RDS y de los hilos de Tomcat (agravado por SEC-016).
* **Coste:** consumo de cuota de proveedores facturados por uso (Celmedia, Modellica, FacePhi) y de RCU/WCU de DynamoDB.
* **Reputacional:** envío de correo desde la identidad corporativa a destinatarios elegidos por el solicitante.

#### Remediación

Defensa en dos planos, porque el borde no cubre el interior:

**1. Acotar la amplificación en el contrato y en el código:**

```yaml
# digitalsignatureapi.yaml — recomendado
ApplicationSignDocumentRequest:
  type: array
  minItems: 1
  maxItems: 10                      # límite explícito
  items:
    type: object
    required: [idDocumento, page, position]
    properties:
      idDocumento: { type: string, maxLength: 64, pattern: '^[A-Za-z0-9._-]+$' }
```

```java
// Código recomendado — validación defensiva además del contrato
if (request.getDocumentos() == null || request.getDocumentos().isEmpty()
        || request.getDocumentos().size() > MAX_DOCUMENTS_PER_BATCH) {
    throw new BusinessException(HttpStatus.BAD_REQUEST, List.of(Exceptions.TL0002));
}
```

**2. Limitar por sujeto en las operaciones sensibles**, no solo por IP en el borde:

```java
// Código recomendado — beemailboxes
@Bean
public RateLimiterRegistry rateLimiterRegistry() {
    return RateLimiterRegistry.of(RateLimiterConfig.custom()
            .limitForPeriod(3)                            // 3 OTP
            .limitRefreshPeriod(Duration.ofMinutes(15))   // por cada 15 min
            .timeoutDuration(Duration.ZERO)
            .build());
}

public WrapperSendEmail sendMailing(WrapperRequestSendEmail criteria, String flow) {
    RateLimiter limiter = registry.rateLimiter("otp:" + subjectId(criteria));
    if (!limiter.acquirePermission()) {
        throw new BusinessException(HttpStatus.TOO_MANY_REQUESTS, List.of(Exceptions.TL0019));
    }
    ...
}
```

**3. Configurar cuotas por `client_id` en el API Gateway** (usage plans) además de las reglas volumétricas de Imperva, y **añadir circuit breakers** (Resilience4j) en las llamadas a proveedores para que su degradación no se propague.

---

### SEC-020 — Payloads base64 sin límite de tamaño ni restricciones de formato

**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-400, CWE-20 (Improper Input Validation) · **OWASP:** API4:2023
**Proyecto/API:** bedigitsignature, bedocmanagement, beidentbiometric, beclaims

#### Ubicación

```text
bedigitsignature · api/digitalsignatureapi.yaml:251-280  · ApplicationSignatureRequest (sin required, sin maxLength)
bedocmanagement  · openapi.yaml (0 maxLength, 0 pattern en todo el fichero)
beclaims         · api/claimsapi.yaml (0 maxLength, 0 pattern)
bedocmanagement  · DocumentManagementAdapter.java:115  · Base64.getDecoder().decode(...)
```

#### Descripción

Los contratos de los servicios que reciben documentos e imágenes carecen de restricciones. El caso más claro:

```yaml
# digitalsignatureapi.yaml:251-267
ApplicationSignatureRequest:
  type: object
  properties:                     # <-- sin bloque 'required'
    nombre:    { type: string, example: Miguel }
    apellido:  { type: string, example: Quezada }
    dni:       { type: string, example: 783582695 }
    foto:      { type: string, example: "JPEG/PNG en base 64" }   # <-- sin maxLength
    documentos:
      $ref: '#/components/schemas/ApplicationSignDocumentRequest' # <-- array sin maxItems
```

Recuento de restricciones por contrato:

| Contrato | `maxLength` | `pattern` |
| -------- | ----------: | --------: |
| beclaims | 0 | 0 |
| bedigitsignature | 0 | 0 |
| bedocmanagement | 0 | 0 |
| becreditrisk | 1 | 0 |
| beknowyocustomer | 54 | 50 |

`beknowyocustomer` demuestra que el estándar existe y se aplica correctamente en algunos contratos; los que manejan binarios son precisamente los que carecen de él.

En el código, el contenido se materializa íntegro en memoria antes de cualquier comprobación:

```java
// bedocmanagement/DocumentManagementAdapter.java:115
byte[] fileBytes = Base64.getDecoder().decode(document.getFolderReference());
```

`spring.servlet.multipart.max-file-size: 50MB` está configurado en varios perfiles, pero **no aplica**: el contenido no viaja como multipart sino como cadena base64 dentro de un JSON. Para el cuerpo JSON no hay límite configurado, y `server.max-http-request-header-size: 128KB` solo acota las cabeceras.

Como `foto`, `documentos` y los campos de identidad carecen incluso de `required`, el código recibe `null` donde asume valor, lo que enlaza con SEC-028.

#### Escenario de explotación

Enviar un cuerpo JSON con un base64 de varios cientos de MB. El servicio lo decodifica completo en el heap (`decode` asigna un array del tamaño resultante), lo re-codifica para el log (SEC-011) y lo mantiene en memoria durante toda la llamada al proveedor. Con peticiones concurrentes se alcanza `OutOfMemoryError` y el pod se reinicia. Repetido, produce un ciclo de reinicios que deja el servicio permanentemente indisponible.

#### Impacto

* **Disponibilidad:** agotamiento de memoria y reinicio de pods.
* **Coste:** volumen desproporcionado de logs (agravado por SEC-011) y de almacenamiento en S3.

#### Remediación

```yaml
# Recomendado — contrato
ApplicationSignatureRequest:
  type: object
  required: [nombre, apellido, dni, documentos]
  properties:
    nombre:   { type: string, minLength: 1, maxLength: 80,  pattern: "^[\\p{L} .'-]+$" }
    apellido: { type: string, minLength: 1, maxLength: 80,  pattern: "^[\\p{L} .'-]+$" }
    dni:      { type: string, pattern: "^[0-9]{8}$" }
    foto:     { type: string, maxLength: 2800000 }        # ~2 MB en base64
    documentos:
      type: array
      minItems: 1
      maxItems: 10
```

```java
// Recomendado — validación defensiva en el adaptador
private static final int MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;

byte[] fileBytes;
try {
    String content = document.getFolderReference();
    if (content.length() > (MAX_DOCUMENT_BYTES / 3) * 4 + 4) {          // longitud base64
        throw new BadRequestException("archivo_excede_tamano",
                "El documento supera el tamaño máximo permitido");
    }
    fileBytes = Base64.getDecoder().decode(content);
} catch (IllegalArgumentException ex) {
    throw new BadRequestException("base64_invalido", "El formato base64 del archivo es inválido");
}
```

Y limitar el tamaño del cuerpo a nivel de servidor y de gateway:

```yaml
server:
  tomcat:
    max-swallow-size: 12MB
    max-http-form-post-size: 12MB
```

Añadir además el límite equivalente en el API Gateway, para que el cuerpo excesivo se rechace antes de alcanzar el pod.

---

### SEC-021 — Endpoint interno expuesto en el contrato público y confianza transitiva entre APIs

**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-668 (Exposure of Resource to Wrong Sphere), CWE-441 · **OWASP:** API1:2023 · API5:2023
**Proyecto/API:** bedocmanagement ← bedigitsignature

#### Ubicación

```text
bedocmanagement  · src/main/resources/openapi.yaml:272 · POST /download_document_intern
bedocmanagement  · DocumentManagementApiDelegateImpl.java:57-61
bedocmanagement  · DocumentManagementAdapter.java:240-274 (downloadDocumentIntern, generateDownloadUrlIntern)
bedigitsignature · infrastructure/utils/Constant.java:21 · POST_DOCUMENT
bedigitsignature · infrastructure/config/WebClientConfig.java:37-50 · documentWebClient
bedigitsignature · src/main/resources/config/application.yml · clients.document.x-santander-client-id: 123
```

#### Descripción

`bedocmanagement` publica dos operaciones de descarga en el mismo contrato:

* `POST /download_document` — devuelve una **URL prefirmada** de S3 con validez de 10 minutos;
* `POST /download_document_intern` — devuelve **el binario completo** del documento en la respuesta.

La segunda, cuyo nombre indica uso interno, está declarada en el mismo `openapi.yaml`, bajo la misma ruta base `/v2/document_management` y con el mismo esquema de seguridad. No hay ninguna separación: ni un contrato distinto, ni un puerto distinto, ni un `scope` diferenciado, ni un `securityScheme` propio.

`bedigitsignature` la consume con un cliente que envía **credenciales estáticas y triviales**:

```java
// bedigitsignature/WebClientConfig.java:38-50
@Bean
public WebClient documentWebClient(WebClient.Builder builder, DocumentApiProperties properties) {
    return builder
            .baseUrl(properties.baseUrl())
            .defaultHeaders(headers -> {
                headers.set("channel", properties.channel());                     // "App-Nube"
                headers.set("society", properties.society());                     // "scp"
                headers.set("x-santander-client-id", properties.xSantanderClientId());  // "123"
            })
            .build();
}
```

```yaml
# bedigitsignature/src/main/resources/config/application.yml
clients:
  document:
    base-url: ${DOCUMENT_URL}
    x-santander-client-id: 123        # <-- literal, en el fichero base, sin variable de entorno
    channel: App-Nube
    society: scp
```

Y `bedocmanagement` **no valida ninguna de esas tres cabeceras**: no hay un solo `getHeader(...)` ni `@RequestHeader` en todo el proyecto. Son decorativas. La confianza es incondicional.

Esto configura el patrón de confianza transitiva descrito en el modelo de amenazas:

```text
Consumidor externo
   ↓ (autenticado por Cognito en el borde, pero sin autorización de objeto — SEC-002)
bedigitsignature   ← acepta cualquier documentId sin comprobar propiedad
   ↓ (llamada este-oeste, sin autenticación — SEC-001)
bedocmanagement    ← confía en que quien llama ya validó
   ↓
S3: binario completo del documento
```

Ninguno de los dos valida. El primero asume que el borde lo hizo; el segundo asume que el primero lo hizo.

#### Flujo (cadena completa)

```text
POST /v1/signature/signer  { "documentos": [ { "idDocumento": "<id ajeno>" } ] }
   ↓
DocumentProcessService.processDocument()
   ↓
DocumentClient.getDocument(documentId)
   ↓
POST {DOCUMENT_URL}/v2/document_management/download_document_intern
      headers: channel=App-Nube, society=scp, x-santander-client-id=123
   ↓
DocumentManagementAdapter.downloadDocumentIntern()  ← sin autorización
   ↓
s3Client.getObject(...)  → InputStreamResource
   ↓
DocumentClient.downloadAsBase64()  → log.info("archivo en base64: {}") (SEC-011)
```

#### Source

`documentos[].idDocumento` del cuerpo de la petición de firma; o, en acceso directo, `document.documentId` del cuerpo de `download_document_intern`.

#### Sink

`s3Client.getObject()` y el binario devuelto.

#### Escenario de explotación

* **Vía externa:** un usuario autenticado por Cognito solicita la firma de un `idDocumento` que no le pertenece. `bedigitsignature` no comprueba propiedad, `bedocmanagement` tampoco, y el contenido del documento acaba en el log (SEC-011) y en la petición al proveedor de firma.
* **Vía este-oeste:** cualquier pod del VPC invoca directamente `download_document_intern` con las tres cabeceras conocidas —publicadas en el repositorio— y descarga cualquier documento del bucket, evitando por completo Akamai, Imperva, el WAF, Cognito y el API Gateway.

#### Impacto

* **Confidencialidad:** descarga arbitraria de documentos contractuales y de identidad.
* **Arquitectura:** un endpoint destinado a consumo interno publicado con el mismo nivel de exposición que las operaciones de cliente.

#### Remediación

1. **Separar el plano interno del externo.** Retirar `download_document_intern` del contrato público y publicarlo en un contrato interno, con su propio `securityScheme` y un `scope` dedicado:

```yaml
# openapi-internal.yaml — recomendado
components:
  securitySchemes:
    ServiceAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
security:
  - ServiceAuth: [document.read.internal]
```

2. **Autenticar la llamada entre servicios.** Sustituir las cabeceras estáticas por un token de cliente obtenido por client-credentials contra Cognito, o —preferible— mTLS de malla con identidad de workload:

```java
// Código vulnerable
.defaultHeaders(headers -> {
    headers.set("x-santander-client-id", properties.xSantanderClientId());  // "123"
})

// Código recomendado
.filter((request, next) -> serviceTokenProvider.getToken()      // client_credentials + scope
        .flatMap(token -> next.exchange(ClientRequest.from(request)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build())))
```

3. **Validar en el receptor.** `bedocmanagement` debe exigir el `scope` interno y aplicar autorización de objeto (SEC-002) — no dar por hecho que el llamante ya validó.
4. **Aislar en red.** `NetworkPolicy` que restrinja el acceso al puerto de `bedocmanagement` a los pods que legítimamente lo consumen.
5. Eliminar el literal `x-santander-client-id: 123` del `application.yml` base y externalizarlo (relacionado con SEC-003).

---

### SEC-022 — Actuator accesible sin autenticación con detalle completo

**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-200, CWE-732 · **OWASP:** API8:2023 · **Proyecto/API:** todos

#### Ubicación

```text
<cada-proyecto>/src/main/resources/config/application.yml
  management.endpoint.health.show-details: ALWAYS
<cada-proyecto>/.../infrastructure/config/SecurityConfig.java
  .requestMatchers(HttpMethod.GET, "/actuator/**").permitAll()
```

#### Descripción

Los once servicios exponen `/actuator/**` con `permitAll` explícito y `show-details: ALWAYS`, sin restringir el conjunto de endpoints publicados (`management.endpoints.web.exposure.include` no aparece en ninguna configuración, por lo que rige el valor por defecto de Spring Boot: `health` e `info`).

Con `show-details: ALWAYS`, `/actuator/health` publica el detalle de cada indicador: estado y detalles del `DataSource` (incluido el producto y la versión de base de datos), `diskSpace` con rutas y capacidad, y el estado de los indicadores personalizados. Es información de reconocimiento directa sobre la infraestructura interna.

**El riesgo mayor es condicional pero relevante.** Si en algún momento se ampliara la exposición —por ejemplo `management.endpoints.web.exposure.include: "*"`, un cambio de una línea y práctica habitual en diagnóstico— quedarían accesibles sin autenticación:

* `/actuator/env` y `/actuator/configprops` — **todas las propiedades de configuración, incluidos los secretos** de SEC-003 resueltos en tiempo de ejecución (Spring enmascara por patrón de nombre, pero `sky.key`, `qurable.token` o `aes.secret` no siempre encajan en los patrones por defecto);
* `/actuator/loggers` — permite **elevar el nivel de log en caliente** vía `POST`, lo que activa el volcado de `wiretap` (SEC-013) y convierte ese hallazgo en explotable remotamente;
* `/actuator/heapdump` — volcado completo de memoria, con tokens y datos en claro;
* `/actuator/mappings`, `/beans`, `/threaddump`.

En el estado actual, con la exposición por defecto, solo `health` e `info` están accesibles. Se clasifica como High por el detalle expuesto, por el `permitAll` explícito que anula cualquier protección del framework, y porque el margen entre el estado actual y el escenario grave es un único cambio de configuración.

#### Escenario de explotación

Desde el plano este-oeste (SEC-001), cualquier pod consulta `/actuator/health` de los once servicios y obtiene un mapa de la infraestructura: qué servicios usan qué bases de datos, su estado y su versión. Si la exposición se amplía, `POST /actuator/loggers/reactor.netty.http.client.HttpClient` con `{"configuredLevel":"DEBUG"}` activa el volcado de todo el tráfico con credenciales, sin autenticación.

#### Impacto

* **Confidencialidad:** reconocimiento de infraestructura; potencialmente secretos y volcados de memoria.
* **Integridad operativa:** modificación del nivel de log en producción sin autenticación.

#### Remediación

```yaml
# Código vulnerable
management:
  endpoint.health:
    show-details: ALWAYS
```

```yaml
# Código recomendado
management:
  endpoints:
    web:
      exposure:
        include: health,info,prometheus      # lista blanca explícita
      base-path: /actuator
  endpoint:
    health:
      show-details: when-authorized          # detalle solo con rol autorizado
      probes:
        enabled: true                        # /health/liveness y /health/readiness
  server:
    port: 8081                               # puerto de gestión separado, no publicado en el NLB
```

```java
// Código recomendado — SecurityConfig
.requestMatchers(HttpMethod.GET, "/actuator/health/liveness",
                                 "/actuator/health/readiness").permitAll()   // sondas de K8s
.requestMatchers("/actuator/**").hasAuthority("SCOPE_ops.monitor")
```

Publicar el actuator en un puerto separado (`management.server.port`) y no incluirlo en el `Service` expuesto al NLB es la medida más efectiva: las sondas de Kubernetes acceden por el puerto de gestión y ningún consumidor externo lo alcanza.

---

### SEC-023 — Debilidades en la emisión de JWT máquina-a-máquina

> ### ⏸️ APLAZADO en v1.7 (2026-09-03) — fuera del alcance de este Ethical Hacking
>
> Sus dos mitades quedan fuera: `becustombeprogrm` por componente, y en `bedigitsignature` el `JwtUtil` cuyo único consumidor es la cabecera del **callback** de retorno — la parte de recepción.
>
> **El hallazgo sigue siendo válido y sigue abierto.** No se ha corregido nada: el código permanece desplegado y el defecto es explotable por quien tenga acceso a ese componente. Lo único que cambia es que **no se mide contra este ejercicio** y no cuenta en los 47 hallazgos de alcance — sí en los 56 de deuda técnica. Se conserva íntegro, con su evidencia y su remediación, para que al volver a alcance recupere su historial en lugar de reaparecer como hallazgo nuevo.

> ### 🟡 Estado en v1.5 (re-verificado 2026-08-31) — **ATENUADO · High → Medium**
>
> Dos de los tres defectos se han corregido en `becustombeprogrm`:
>
> * **Expiración**: `SkyTokenService:45` pasa de `now + 1000 * 20` (20 segundos) a `now + 1000 * 60 * 60` (una hora), que es lo que el comentario decía desde el principio.
> * **Reutilización de clave**: la configuración separa hoy `aes.secret` (`${SEC_SKY_ENCRYPT_SECRET}`) de `jwt.secret` (`${SEC_SKY_JWT_SECRET}`) en los cuatro perfiles. Ya no son el mismo material criptográfico.
>
> **Lo que persiste:**
>
> * Ningún token lleva `iss`, `aud`, `jti` ni `sub`. El único claim es `partnerId: "BSPE"`, marcado en el propio código como `// opcional`.
> * `bedigitsignature/…/utils/JwtUtil.java:39` **conserva la expiración de 20 segundos** con el mismo comentario erróneo `// 1 hora`. La corrección se aplicó a un servicio y no al otro que compartía el defecto — el patrón que §23 marca como riesgo de regresión.
> * `bedigitsignature/application.yml:58` declara `secret: ${SEC_SKY_JWT_SECRET:12}`. Ese `12` por defecto son 2 bytes: si la variable no se inyecta, `Keys.hmacShaKeyFor` recibe una clave muy por debajo de los 256 bits que HS256 exige. Ver SEC-056.


**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-1270 (Generation of Incorrect Security Tokens), CWE-613 (Insufficient Session Expiration), CWE-1204 (Generation of Weak Initialization Vector — por reutilización de clave)
**OWASP:** API2:2023 · **Proyecto/API:** becustombeprogrm, bedigitsignature

#### Ubicación

```text
becustombeprogrm · .../adapters/output/external/SkyTokenService.java:36-53
becustombeprogrm · src/main/resources/config/application-local.yml:13-17
bedigitsignature · .../infrastructure/utils/JwtUtil.java:30-47
```

#### Descripción

Los tokens que estos servicios emiten hacia sus proveedores presentan cuatro defectos:

```java
// SkyTokenService.java:36-53
public String generateToken() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("partnerId", "BSPE"); // opcional

    SecretKey secretKey = Keys.hmacShaKeyFor(
            jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));

    long now = System.currentTimeMillis();
    long expiration = now + 1000 * 60 * 60; // 1 hora

    return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(new Date(now))
            .setExpiration(new Date(expiration))
            .signWith(secretKey, SignatureAlgorithm.HS256)
            .compact();
}
```

**(a) Sin `iss`, `aud` ni `jti`.** El token no declara emisor ni destinatario, por lo que el receptor no puede verificar que fue emitido para él. Si el mismo secreto se usa con dos proveedores, un token emitido para uno es válido en el otro. La ausencia de `jti` impide cualquier control anti-replay (SEC-037).

**(b) La clave AES y la clave de firma JWT son el mismo valor.**

```yaml
# becustombeprogrm/application-local.yml:13-17
aes:
  method: /CBC/PKCS5Padding
  secret: 9b7c2d4e…9d01        # 64 hex = 32 bytes

jwt:
  secret: 9b7c2d4e…9d01        # <-- idéntico
```

Y en los perfiles superiores se mantienen como dos variables distintas (`SEC_SKY_ENCRYPT_SECRET`, `SEC_SKY_JWT_SECRET`), pero nada garantiza que se les asigne un valor diferente. Reutilizar una clave para cifrado simétrico y para firma HMAC viola la separación de propósito criptográfico: el compromiso de una operación compromete la otra, y ciertos ataques sobre uno de los usos pueden filtrar información del otro. Además, esa clave se escribe en los logs (SEC-007).

**(c) Expiración de 20 segundos en `bedigitsignature`, documentada como una hora.**

```java
// JwtUtil.java:38-39
long now = System.currentTimeMillis();
long expiration = now + 1000 * 20; // 1 hora
```

`1000 * 20` son 20 segundos. El comentario dice lo contrario. Este token está destinado al callback de firma (SEC-006), que se dispara cuando la persona firma el documento — minutos u horas después. El token estaría siempre expirado. Actualmente el defecto queda enmascarado porque el token ni siquiera llega a enviarse (bug de `replace`, SEC-006).

**(d) API obsoleta.** `setClaims`, `setIssuedAt`, `setExpiration` y `signWith(key, SignatureAlgorithm)` están deprecados desde jjwt 0.12; el proyecto usa 0.11.5 (SEC-034). Además, `setClaims(map)` **reemplaza** el conjunto de claims, por lo que cualquier claim registrado añadido antes se perdería.

#### Impacto

* **Confidencialidad e integridad:** un token sin `aud` es reutilizable frente a cualquier receptor que comparta el secreto; la reutilización de clave amplía el radio de un compromiso.
* **Disponibilidad funcional:** con 20 segundos de vida, el callback de firma no puede autenticarse — el flujo no cierra.
* **Trazabilidad:** sin `jti` no hay forma de invalidar un token concreto ni de detectar su reutilización.

#### Remediación

```java
// Código vulnerable
return Jwts.builder()
        .setClaims(claims)
        .setIssuedAt(new Date(now))
        .setExpiration(new Date(expiration))
        .signWith(secretKey, SignatureAlgorithm.HS256)
        .compact();
```

```java
// Código recomendado (jjwt 0.12.x)
public String generateToken(String audience, Duration ttl) {
    Instant now = Instant.now();
    return Jwts.builder()
            .issuer("cpe-nxhbsc-becustombeprogrm")
            .audience().add(audience).and()
            .subject(partnerId)
            .id(UUID.randomUUID().toString())            // jti
            .claim("partnerId", "BSPE")
            .issuedAt(Date.from(now))
            .notBefore(Date.from(now))
            .expiration(Date.from(now.plus(ttl)))
            .signWith(signingKey, Jwts.SIG.HS256)
            .compact();
}
```

Y en configuración:

```yaml
# Recomendado — claves separadas, sin valores por defecto
aes:
  method: ${SEC_SKY_ENCRYPT_METHOD}
  secret: ${SEC_SKY_ENCRYPT_SECRET}      # clave de cifrado, exclusiva

jwt:
  secret: ${SEC_SKY_JWT_SECRET}          # clave de firma, distinta y rotada por separado
  ttl-seconds: ${SKY_JWT_TTL:3600}
```

Acciones adicionales:

1. **Verificar en el arranque que `aes.secret != jwt.secret`** y fallar si coinciden.
2. Corregir la expiración de `bedigitsignature` y externalizarla; un TTL de callback debe cubrir el tiempo real del proceso de firma (SEC-006).
3. Migrar a **jjwt 0.12.x** y actualizar la API (SEC-034).
4. Considerar la migración a claves asimétricas (RS256/ES256) para los tokens dirigidos a terceros: evita compartir un secreto simétrico con el proveedor y permite rotación sin coordinación.

---

### SEC-047 — Enumeración diferencial: tres respuestas distintas ante el mismo recurso inexistente

**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-204 (Observable Response Discrepancy), CWE-203
**OWASP:** API1:2023 Broken Object Level Authorization
**Proyecto/API:** cpe-nxhbsc-bedocmanagement

#### Ubicación

```text
Archivo: .../infrastructure/adapters/output/DocumentManagementAdapter.java
Métodos: downloadDocument(...)   · líneas 61-71   → 404
         getDocument(...)        · líneas 178-185 → 200 con objeto vacío
         deleteDocument(...)     · líneas 200-215 → 204
```

#### Descripción

Tres operaciones consultan el mismo registro por el mismo identificador y responden de forma distinta cuando no existe:

```java
// downloadDocument:65-67  → 404
if (fileEntity.isEmpty()) {
  throw new NotFoundException("documento_no_encontrado", "No se encontro el documento solicitado");
}

// getDocument:180-182  → 200 con cuerpo vacío
if(objectMetadataOptional.isEmpty()){
  return new WrapperMySearchDocumentResponse();
}

// deleteDocument:202-204  → 204, igual que si hubiera borrado
if (fileEntityOptional.isEmpty()){
  return null;
}
```

La diferencia entre `404` y `200` convierte el par de endpoints en un **oráculo de existencia**: sin acceder al contenido, el solicitante distingue qué identificadores existen. Es el paso previo habitual a la explotación de SEC-002, y elimina el único obstáculo práctico que tendría un atacante — no conocer los identificadores válidos.

`deleteDocument` devolviendo `204` en ambos casos tiene el problema inverso: oculta si la operación tuvo efecto, lo que dificulta detectar un borrado abusivo en los registros.

#### Flujo

```text
GET /v2/document_management/documents/<id-candidato>
   ↓
200 + cuerpo vacío  → el identificador NO existe
200 + metadatos     → el identificador SÍ existe  → explotar vía SEC-002/SEC-048
```

#### Source

`document_id` (path) y `document.documentId` (cuerpo).

#### Sink

Código de estado y forma del cuerpo de la respuesta.

#### Escenario de explotación

Iterar identificadores contra `GET /documents/{id}` y quedarse con los que devuelven cuerpo no vacío. Se obtiene el inventario de identificadores válidos sin generar un solo error, lo que además reduce la probabilidad de disparar alertas basadas en tasa de 4xx.

#### Impacto

* **Confidencialidad:** habilita la explotación dirigida de SEC-002, SEC-048 y SEC-049.
* **Detección:** un barrido que solo produce respuestas 200 es más difícil de detectar que uno que genera 404 masivos.

#### Remediación

Unificar el comportamiento: la misma condición debe producir la misma respuesta en las tres operaciones, y esa respuesta debe ser `404` **después** de comprobar la titularidad (ver SEC-002), de modo que "no existe" y "no es tuyo" sean indistinguibles.

```java
// Código vulnerable — tres comportamientos distintos
if(objectMetadataOptional.isEmpty()){
  return new WrapperMySearchDocumentResponse();      // 200 vacío
}

// Código recomendado — comportamiento único
FileEntity file = repository.getByKey(documentId, null)
        .filter(f -> authorizationService.puedeAcceder(currentPrincipal(), f))
        .orElseThrow(() -> new NotFoundException(
                "documento_no_encontrado", "No se encontró el documento solicitado"));
```

Devolver `404` en lugar de `403` cuando el documento existe pero pertenece a otro titular es deliberado: un `403` confirmaría su existencia.

---

### SEC-048 — El documento de identidad del titular se devuelve en los metadatos

> ### 🟡 Estado en v1.6 (re-verificado 2026-09-03) — **ATENUADO · High → Medium · remediación incompleta**
>
> `getMapper`, que era el método señalado en v1.5, **está corregido**: ahora devuelve el nombre real del fichero.
>
> ```java
> // DocumentMapper.java:111-118  — CORREGIDO
> public WrapperMySearchDocumentResponse getMapper(FileEntity entity){
>   response.setName(entity.getFileName());        // antes: entity.getName(), que es el DNI
>   response.setDocumentId(entity.getCustomerId());
>   ...
> }
> ```
>
> Pero **`searchMapper`, en el mismo fichero y 60 líneas más arriba, no se tocó**:
>
> ```java
> // DocumentMapper.java:44-55  — SIN CAMBIOS
> wrapper.setDocumentId(objectSumary.getCustomerId());
> wrapper.setName(objectSumary.getName());       // <-- getName() sigue siendo el ownerId (DNI)
> ```
>
> Y `FileEntity.getName()` sigue alimentado con el DNI en `toEntity:78-82` (`entity.setName(documentRequest.getOwners().get(0).getOwnerId())`).
>
> El resultado práctico es que la exposición **se ha desplazado, no eliminado**: `GET /documents/{id}` ya no revela el DNI, pero `POST /search_documents` sí — y ese es el endpoint que devuelve muchos registros por llamada, no uno. En términos de volumen de PII expuesta, el endpoint que quedó sin corregir es el peor de los dos. Ver **SEC-058**.
>
> Baja a Medium porque el vector individual desaparece; no se cierra porque el vector masivo sigue.

**Severidad:** ~~High~~ **Medium** · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-359 (Exposure of Private Personal Information), CWE-213
**OWASP:** API3:2023 Broken Object Property Level Authorization
**Proyecto/API:** cpe-nxhbsc-bedocmanagement

#### Ubicación

```text
Archivo: .../infrastructure/adapters/output/DocumentMapper.java
Métodos: toEntity(...)  · líneas 71-90   (escritura)
         getMapper(...) · líneas 111-118 (lectura)
```

#### Descripción

En la subida, el identificador del titular se almacena en el campo `name` de la entidad:

```java
// DocumentMapper.java:78-82
if (documentRequest.getOwners().isEmpty()){
    entity.setName("NUBE");
} else {
    entity.setName(documentRequest.getOwners().get(0).getOwnerId());   // <-- DNI del titular
}
```

Y en la consulta de metadatos ese mismo campo se publica en la respuesta:

```java
// DocumentMapper.java:111-118
public WrapperMySearchDocumentResponse getMapper(FileEntity entity){
    WrapperMySearchDocumentResponse response = new WrapperMySearchDocumentResponse();
    response.setName(entity.getName());                 // <-- devuelve el ownerId
    response.setDocumentId(entity.getCustomerId());
    ...
}
```

El campo `name` de la respuesta —que por su nombre parecería el nombre del documento— contiene en realidad el **documento de identidad del titular**. El nombre real del fichero está en `fileName`, que no se devuelve (ver SEC-051).

#### Flujo

```text
GET /v2/document_management/documents/{document_id}
   ↓
DocumentManagementAdapter.getDocument()
   ↓
DocumentMapper.getMapper()  → response.name = FileEntity.name = ownerId
   ↓
200 {"name": "<DNI del titular>", "documentId": "...", ...}
```

#### Source

`document_id` en la ruta, sin control de titularidad (SEC-002).

#### Sink

Cuerpo de la respuesta HTTP.

#### Escenario de explotación

Encadenado, produce la extracción completa del repositorio documental con su titular:

```text
SEC-014  GET /documents/{cualquiera}/versions  → nombres de fichero de TODOS los documentos
SEC-047  GET /documents/{id}                   → identificar cuáles existen
SEC-048  GET /documents/{id}                   → DNI del titular de cada uno
```

Dos llamadas por documento bastan para construir la relación completa *documento → titular*.

#### Impacto

* **Confidencialidad:** exposición de datos personales identificativos asociados a documentación contractual.
* **Cumplimiento:** tratamiento y divulgación de identificadores personales fuera de la finalidad de la operación (Ley 29733).

#### Remediación

```java
// Código vulnerable
response.setName(entity.getName());        // ownerId

// Código recomendado — devolver el nombre del fichero, no el titular
response.setName(entity.getFileName());
```

Y corregir el modelo para que el titular viaje en un campo con nombre correcto y solo se devuelva cuando el solicitante sea ese titular:

```java
// Código recomendado
if (authorizationService.esTitular(currentPrincipal(), entity)) {
    response.setOwnerId(mask(entity.getOwnerId()));   // enmascarado incluso para el titular
}
```

Revisar en la misma línea el resto de `WrapperMySearchDocumentResponse`: aplicar el principio de mínima exposición y devolver solo los campos que el consumidor necesita.

---

### SEC-049 — Borrado de documentos sin verificación de titularidad ni de existencia

> ### 🟢 Estado en v1.6 (re-verificado 2026-09-03) — **ATENUADO · High → Low**
>
> Dos cambios, y el segundo es el determinante.
>
> **(1) Ya comprueba existencia.** `deleteDocument` recupera la entidad antes de borrar y lanza `NotFoundException` si no está, en lugar de emitir un `DeleteObjectRequest` contra S3 con una clave arbitraria:
>
> ```java
> // DocumentManagementAdapter.java:200-217
> Optional<FileEntity> fileEntityOptional = repository.getByKey(documentId,null);
> if (fileEntityOptional.isEmpty()) {
>   throw new NotFoundException(Constant.NOT_FOUND_CODE, Constant.NOT_FOUND_TEXT);
> }
> ```
>
> **(2) No es alcanzable desde el exterior.** `DocumentManagementApiDelegateImpl.removeDocument` (línea 95) **no lleva `@Override`** y no corresponde a ningún método de los delegates que la clase implementa; el contrato `openapi.yaml` tampoco declara ninguna operación `DELETE`. No hay controlador generado que lo invoque: es código inerte.
>
> **Por qué Low y no cerrado.** Sigue sin verificar titularidad, y basta con declarar la operación en el contrato — un cambio de cinco líneas de YAML — para que el borrado ajeno vuelva a ser explotable de inmediato. Se deja abierto como Low para que, cuando esa operación se publique, la comprobación de titularidad se añada en el mismo cambio y no después.

**Severidad:** ~~High~~ **Low** · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-284
**OWASP:** API1:2023 Broken Object Level Authorization
**Proyecto/API:** cpe-nxhbsc-bedocmanagement

#### Ubicación

```text
Archivo: .../infrastructure/adapters/output/DocumentManagementAdapter.java
Método:  deleteDocument(String documentId)  · líneas 200-215
Endpoint: DELETE /v2/document_management/documents/{document_id}
```

#### Descripción

```java
@Override
public Void deleteDocument(String documentId) {
  Optional<FileEntity> fileEntityOptional = repository.getByKey(documentId,null);
  if (fileEntityOptional.isEmpty()){
    return null;                                  // 204, como si hubiera borrado
  }
  FileEntity fileEntity = fileEntityOptional.get();

  String key = fileEntity.getUrl();
  s3Client.deleteObject(DeleteObjectRequest.builder()
          .bucket(bucketName).key(key).build());  // borra el objeto en S3
  repository.delete(fileEntity);                  // y el registro en DynamoDB
  return null;
}
```

El identificador llega del solicitante y **no se comprueba a quién pertenece el documento**. La operación es destructiva y afecta a los dos almacenes: el binario en S3 y la metadata en DynamoDB.

Agrava el problema que el bucket no tenga versionado verificable desde el código (SEC-015): sin él, el borrado es irreversible.

Además devuelve `204` tanto si borró como si el documento no existía, lo que impide distinguir en los registros un borrado real de un intento fallido.

#### Flujo

```text
DELETE /v2/document_management/documents/<id ajeno>
Authorization: Bearer <token válido de cualquier consumidor>
   ↓
DocumentManagementApiDelegateImpl.removeDocument()
   ↓
deleteDocument()  ← sin comprobación de titularidad
   ↓
s3Client.deleteObject()  +  repository.delete()
   ↓
204 No Content
```

#### Source

`document_id` en la ruta.

#### Sink

`s3Client.deleteObject()` y `repository.delete()`.

#### Escenario de explotación

Con los identificadores obtenidos vía SEC-014 y SEC-047, un consumidor con token válido puede eliminar documentación contractual de cualquier cliente. No requiere privilegios especiales ni conocimiento interno: el `document_id` es el único dato necesario, y es enumerable.

#### Impacto

* **Integridad y disponibilidad:** destrucción de documentación contractual, potencialmente irreversible.
* **Negocio y cumplimiento:** pérdida de evidencia documental con valor probatorio; posible incumplimiento de obligaciones de conservación.

#### Remediación

```java
// Código recomendado
@Override
public Void deleteDocument(String documentId) {
  FileEntity file = repository.getByKey(documentId, null)
          .orElseThrow(() -> new NotFoundException(
                  "documento_no_encontrado", "No se encontró el documento solicitado"));

  authorizationService.assertEsTitular(currentPrincipal(), file);   // 404 si no lo es

  auditService.registrarBorrado(currentPrincipal(), documentId);    // traza previa

  s3Client.deleteObject(DeleteObjectRequest.builder()
          .bucket(bucketName).key(file.getUrl()).build());
  repository.delete(file);
  return null;
}
```

Complementariamente, y con independencia del control de acceso:

1. **Activar versionado en el bucket** para que un borrado sea reversible.
2. **Considerar borrado lógico** (`status = deleted` + TTL) en lugar de físico, dado el valor probatorio de estos documentos.
3. **Auditar toda operación destructiva** con el principal, el objeto y la marca temporal.

---

### SEC-053 — La limitación de OTP añadida cubre la generación pero no la validación

**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-770 (Allocation Without Limits)
**OWASP:** API2:2023 Broken Authentication · API4:2023 Unrestricted Resource Consumption
**Proyecto/API:** cpe-nxhbsc-beemailboxes
**Nuevo en v1.5.** Deriva del control introducido en este ciclo. Ver SEC-005 y SEC-019.

#### Ubicación

```text
cpe-nxhbsc-beemailboxes/…/infrastructure/config/RateLimiterConfig.java:12-22
cpe-nxhbsc-beemailboxes/…/application/ports/input/EmailboxIdInputPort.java:39-70
```

#### Descripción

El servicio incorpora un limitador de caudal Resilience4j, el primero del conjunto. Está bien planteado en su intención y mal colocado en su alcance: protege la operación que **envía** el código y deja sin proteger la que lo **comprueba**, que es donde ocurre la fuerza bruta.

```java
// EmailboxIdInputPort.java
@Override
public WrapperClassifyEmail validCode(String otp, WrapperRequestClassifyEmails criteria) {
    return otpServiceRepositoryPort.validCode(otp, criteria);      // 40-42 · sin límite alguno
}

@Override
public WrapperSendEmail sendMailing(WrapperRequestSendEmail request, String flow) {
    if ("otp".equalsIgnoreCase(flow)) {
        String email = request.getRecipients().getTo().get(0).getEmailAddress();
        RateLimiter limiter = rateLimiterRegistry.rateLimiter("otp:" + email);   // 57-58
        if (!limiter.acquirePermission()) {
            throw new HttpBaseException("error", HttpStatus.TOO_MANY_REQUESTS, "Demasiados intentos", "TL0019");
        }
    }
    return otpServiceRepositoryPort.sendMailing(request, flow);
}
```

Tres problemas distintos, en orden de gravedad:

**1. La validación sigue sin límite.** `POST /v1/emailboxes/{id}/emails/{OTP}/classify_email` admite intentos ilimitados. Combinado con SEC-005 —`validCode` busca el OTP como clave primaria en DynamoDB, sin vincularlo a usuario ni operación, y da por buena cualquier respuesta no nula— el espacio a recorrer no es el de "el OTP de esta operación" sino **el de cualquier OTP vivo en la tabla**. Cuantos más usuarios haya operando a la vez, más fácil es acertar. Es el problema clásico de la colisión de cumpleaños aplicado a un segundo factor.

**2. El registro crece sin cota, indexado por entrada del cliente.** `rateLimiterRegistry.rateLimiter(name)` crea una entrada si no existe y **no la elimina nunca**. La clave es `"otp:" + email`, y ese `email` viene del cuerpo de la petición. Un atacante que envíe peticiones con direcciones distintas —incluso rechazadas después— hace crecer el mapa indefinidamente hasta agotar el heap del pod. La configuración lo agrava: `limitRefreshPeriod` de 15 minutos mantiene cada entrada activa mucho tiempo.

**3. El límite es por pod y por destinatario.** Al vivir en memoria, con *N* réplicas el límite efectivo es 3×*N* por ventana, y se reinicia en cada despliegue. Y al estar indexado por destinatario, no limita el envío masivo **a direcciones distintas**: cada dirección estrena su propio cupo. El escenario de abuso de mensajería que motivó SEC-019 sigue abierto.

#### Escenario de explotación

```http
POST /v1/emailboxes/{id}/emails/00000001/classify_email     → repetir sin límite
Authorization: Bearer <token válido de Cognito>
```

Ninguna de las cuatro capas de perímetro cuenta intentos por identificador de recurso. El WAF verá peticiones bien formadas y autenticadas hacia rutas distintas.

#### Impacto

Fuerza bruta viable sobre el segundo factor, con el que se autorizan operaciones sensibles; y denegación de servicio del propio `beemailboxes` por consumo de memoria, que arrastra consigo el envío de OTP legítimos.

#### Remediación

```java
// 1. Limitar TAMBIÉN la validación, por el sujeto de la operación, no por el código
@Override
public WrapperClassifyEmail validCode(String otp, WrapperRequestClassifyEmails criteria) {
    String subject = criteria.getEmail().getOperationId();          // no el OTP: es lo que se adivina
    RateLimiter limiter = rateLimiterRegistry.rateLimiter("otp-validate:" + subject);
    if (!limiter.acquirePermission()) {
        throw new HttpBaseException("error", HttpStatus.TOO_MANY_REQUESTS, "Demasiados intentos", "TL0019");
    }
    return otpServiceRepositoryPort.validCode(otp, criteria);
}
```

```java
// 2. Acotar el registro: TTL y tamaño máximo, o un Caffeine con expireAfterWrite
@Bean
public RateLimiterRegistry rateLimiterRegistry() {
    return RateLimiterRegistry.of(
        io.github.resilience4j.ratelimiter.RateLimiterConfig.custom()
            .limitForPeriod(3)
            .limitRefreshPeriod(Duration.ofMinutes(15))
            .timeoutDuration(Duration.ZERO)
            .build());
    // …y envolver la obtención en una caché acotada:
    //   Caffeine.newBuilder().maximumSize(50_000).expireAfterAccess(30, MINUTES)
}
```

**El porqué del cambio de clave.** Limitar por el valor que se está adivinando no sirve de nada: el atacante prueba un código distinto en cada petición, así que cada intento estrena cupo. El contador tiene que colgar de lo que permanece constante durante el ataque —la operación o el usuario—, no de lo que varía.

**Y el porqué del ámbito.** Un contador en memoria es aceptable como defensa en profundidad, pero no como control principal de un segundo factor: con réplicas, el límite real es el que multiplica el número de pods. El contador de intentos de OTP debería vivir junto al propio OTP, en DynamoDB, incrementado de forma condicional en la misma escritura que valida el código.

**Dependencia no declarada.** `io.github.resilience4j` no aparece en `cpe-nxhbsc-beemailboxes/pom.xml`; llega, presumiblemente, como dependencia transitiva del starter corporativo. No se ha podido resolver el árbol de dependencias sin ejecutar Maven, así que esto queda como punto a confirmar: si es transitiva, una subida del parent que deje de arrastrarla rompe la compilación o, peor, la sustituye por otra versión. Declárala explícitamente.

---

### SEC-054 — Dos servicios asumen el rol IAM de otro servicio

**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-269 (Improper Privilege Management), CWE-1268 (Policy Privileges Inconsistent with Access Control)
**OWASP:** API8:2023 Security Misconfiguration
**Proyecto/API:** cpe-nxhbsc-becustombeprogrm, cpe-nxhbsc-bedigitsignature
**Nuevo en v1.5.**

#### Ubicación

```text
cpe-nxhbsc-becustombeprogrm/src/main/resources/config/application-local.yml:35
cpe-nxhbsc-becustombeprogrm/src/main/resources/config/application-cert.yml:34
cpe-nxhbsc-becustombeprogrm/src/main/resources/config/application-pre.yml:34
cpe-nxhbsc-becustombeprogrm/src/main/resources/config/application-pro.yml:34
cpe-nxhbsc-bedigitsignature/src/main/resources/config/application.yml:63
```

#### Descripción

La convención del programa es inequívoca y la cumplen nueve de los once servicios: cada uno asume el rol nombrado con su propio identificador.

```yaml
becreditrisk      → ${AWS_IRSA_BECREDITRISK}
bedatacomanagment → ${AWS_IRSA_BEDATACOMANAGMENT}
bedocmanagement   → ${AWS_IRSA_BEDOCMANAGEMENT}
beemailboxes      → ${AWS_IRSA_BEEMAILBOXES}
beidentbiometric  → ${AWS_IRSA_BEIDENTBIOMETRIC}
beknowyocustomer  → ${AWS_IRSA_BEKNOWYOCUSTOMER}
```

Dos no la cumplen, y en los cuatro perfiles:

```yaml
# cpe-nxhbsc-becustombeprogrm/src/main/resources/config/application-pro.yml:31-35
aws:
  region: ${AWS_TABLE_REGION:us-east-1}
  dynamodb:
    role-arn: ${AWS_IRSA_BEEMAILBOXES:test}      # ← rol de beemailboxes
    regularization-table: ${AWS_TABLE14_NAME}

# cpe-nxhbsc-bedigitsignature/src/main/resources/config/application.yml:60-65
aws:
  bucket: ${AWS_BUCKET01_NAME:xx}
  dynamodb:
    role-arn: ${AWS_IRSA_BEDOCMANAGEMENT:test}   # ← rol de bedocmanagement
```

Cualquiera de las dos lecturas posibles es un hallazgo:

* **Si el despliegue inyecta esa variable con el ARN correcto de cada servicio**, entonces el nombre miente y la próxima persona que toque el chart romperá el despliegue o, sin darse cuenta, dará a un servicio el rol de otro. Es una trampa documental.
* **Si el despliegue inyecta el ARN que el nombre indica** —lo más probable, porque es de donde sale el nombre—, entonces `becustombeprogrm` opera contra DynamoDB con la identidad de `beemailboxes` y `bedigitsignature` con la de `bedocmanagement`. Ese rol tiene que estar sobredimensionado para dar acceso a las tablas de ambos, o la operación falla.

#### Impacto

**Privilegio excesivo.** El rol de `beemailboxes` cubre la tabla de OTP y el bucket de adjuntos; el de `bedocmanagement`, el bucket documental completo y su tabla de metadatos. Un compromiso de `becustombeprogrm` —el servicio con más integraciones externas y el único sin timeout (SEC-016)— alcanza el almacén de OTP. Un compromiso de `bedigitsignature` alcanza S3 documental directamente, sin pasar por `bedocmanagement`, lo que además vuelve irrelevante el control que SEC-021 propone añadir en esa frontera.

**Pérdida de atribución.** En CloudTrail, las llamadas de dos servicios distintos aparecen bajo la misma identidad. Ante un incidente no se puede determinar cuál de los dos pods realizó una operación, que es justamente lo que un modelo IRSA por servicio existe para permitir.

#### Remediación

```yaml
# cpe-nxhbsc-becustombeprogrm — los cuatro perfiles
aws:
  dynamodb:
    role-arn: ${AWS_IRSA_BECUSTOMBEPROGRM}     # sin valor por defecto (ver SEC-056)

# cpe-nxhbsc-bedigitsignature/application.yml
aws:
  dynamodb:
    role-arn: ${AWS_IRSA_BEDIGITSIGNATURE}
```

Y crear los dos roles con una política acotada a los recursos que cada servicio usa realmente: `becustombeprogrm` solo necesita `AWS_TABLE14_NAME`; `bedigitsignature` solo su tabla de lotes de firma.

**El porqué.** IRSA existe para que cada workload tenga una identidad propia y una política mínima. Compartir el rol entre servicios devuelve el modelo al punto de partida —un permiso común para todo— y anula tanto el aislamiento como la trazabilidad. Conviene además añadir una comprobación en CI que verifique que `role-arn` referencia la variable con el nombre del propio componente: es una regla de una línea que impide que el error se repita.

---

### SEC-055 — El despliegue productivo lee un secreto del almacén de desarrollo

> ### ⏸️ APLAZADO en v1.7 (2026-09-03) — fuera del alcance de este Ethical Hacking
>
> Afecta solo a `cpe-nxhbsc-becustombeprogrm` (secreto de Qurable leído del almacén `dev-` en el chart de `pro`), que no entra en el EH.
>
> **El hallazgo sigue siendo válido y sigue abierto.** No se ha corregido nada: el código permanece desplegado y el defecto es explotable por quien tenga acceso a ese componente. Lo único que cambia es que **no se mide contra este ejercicio** y no cuenta en los 47 hallazgos de alcance — sí en los 56 de deuda técnica. Se conserva íntegro, con su evidencia y su remediación, para que al volver a alcance recupere su historial en lugar de reaparecer como hallazgo nuevo.

**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-1188 (Insecure Default Initialization), CWE-798 (Use of Hard-coded Credentials)
**OWASP:** API8:2023 Security Misconfiguration
**Proyecto/API:** cpe-nxhbsc-becustombeprogrm
**Nuevo en v1.5.**

#### Ubicación

```text
cpe-nxhbsc-becustombeprogrm/.gluon/cd/pro/values-pro.yaml:37-42
```

#### Descripción

El manifiesto de despliegue **productivo** define cinco variables desde `secretKeyRef`. Cuatro apuntan al almacén de producción y la quinta, no:

```yaml
# .gluon/cd/pro/values-pro.yaml
extraEnvVars:
  - name: SEC_SKY_JWT_SECRET
    valueFrom: { secretKeyRef: { name: "pro-publickey-nexhub", key: "sky_jwt_secret",        optional: false } }
  - name: SEC_SKY_ENCRYPT_METHOD
    valueFrom: { secretKeyRef: { name: "pro-publickey-nexhub", key: "sky_encrypt_method",    optional: false } }
  - name: SEC_SKY_ENCRYPT_SECRET
    valueFrom: { secretKeyRef: { name: "pro-publickey-nexhub", key: "sky_encrypt_secret",    optional: false } }
  - name: SEC_SKY_SUBSCRIPTION_KEY
    valueFrom: { secretKeyRef: { name: "pro-publickey-nexhub", key: "sky_subscription_key",  optional: false } }
  - name: SEC_QURABLE_JWT_TOKEN
    valueFrom: { secretKeyRef: { name: "dev-publickey-nexhub", key: "qurable_jwt_token",     optional: false } }
                                        # ↑ almacén de DESARROLLO en el chart de PRODUCCIÓN
```

Se ha revisado el mismo patrón en los demás manifiestos: es el **único** cruce de este tipo. Los charts `pre` de `becustombeprogrm` y `beemailboxes` referencian `pre-publickey-nexhub`, y el `pro` de `beemailboxes` referencia `pro-publickey-nexhub`. Nueve de las diez referencias del entorno `pro` son coherentes; esta es la excepción, lo que descarta que sea una convención deliberada del programa.

#### Impacto

* El token JWT con el que el servicio productivo se autentica ante **Qurable** (el proveedor del programa de puntos) es el mismo que usan los entornos de desarrollo. Quien tenga acceso a desarrollo —perímetro mucho más laxo, y donde por definición trabaja más gente— tiene la credencial de producción.
* Rotar el secreto de desarrollo tumba producción. Rotar el de producción no surte efecto: producción no lo lee.
* Si el `Secret` `dev-publickey-nexhub` no existe en el namespace productivo, el pod **no arranca** (`optional: false`). La configuración es, o bien una fuga de credenciales entre entornos, o bien un despliegue roto. Ambas cosas hay que resolverlas antes de subir.

#### Remediación

```yaml
  - name: SEC_QURABLE_JWT_TOKEN
    valueFrom:
      secretKeyRef:
        name: "pro-publickey-nexhub"
        key: "qurable_jwt_token"
        optional: false
```

Y después: dar de alta la clave `qurable_jwt_token` en `pro-publickey-nexhub` con un valor **nuevo**, y **rotar el de desarrollo** — hay que asumir que estuvo compartido.

**El porqué.** El aislamiento entre entornos vale exactamente lo que valga su eslabón más débil: una sola referencia cruzada anula la separación completa. Este defecto es además indetectable en ejecución cuando funciona —el servicio arranca y opera con normalidad— y solo aparece leyendo el manifiesto, que es lo que hace esta revisión. Merece una regla en CI: en un chart de `pro`, ningún `secretKeyRef.name` debe empezar por `dev-` ni `pre-`.

---

### SEC-058 — `search_documents` permite volcar el inventario documental completo, con el DNI de cada titular

**Severidad:** High · **Confianza:** CONFIRMADO · **Prioridad:** P1
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-200 (Exposure of Sensitive Information), CWE-359 (Exposure of Private Personal Information)
**OWASP:** API1:2023 Broken Object Level Authorization · API3:2023 · API4:2023
**Proyecto/API:** cpe-nxhbsc-bedocmanagement
**Nuevo en v1.6.**

#### Ubicación

```text
Contrato: cpe-nxhbsc-bedocmanagement/src/main/resources/openapi.yaml — POST /search_documents
Archivo:  .../infrastructure/adapters/output/DocumentManagementAdapter.java
Metodo:   searchDocuments(WrapperPostSearchDocumentsRequest)   · lineas 80-97
Archivo:  .../infrastructure/adapters/output/jpa/FileSearchMapper.java     · lineas 15-49
Archivo:  .../infrastructure/adapters/output/utils/ExpressionBuilder.java  · lineas 42-67
Archivo:  .../infrastructure/config/BaseDynamoRepository.java              · lineas 76-92
Archivo:  .../infrastructure/adapters/output/DocumentMapper.java           · lineas 44-55
```

#### Descripción

Tres defectos que por separado ya están reportados — el `Scan` sin paginación (SEC-039), la ausencia de autorización de objeto (SEC-002) y el DNI en el campo `name` (SEC-048) — se combinan en este endpoint en algo cualitativamente distinto: **una primitiva de enumeración que devuelve, en una sola llamada, el inventario documental de todos los clientes junto al documento de identidad de cada propietario**.

El filtro lo construye el solicitante. `FileSearchMapper` valida el **campo** contra un enum y el **operador** contra otro enum — lo cual, correctamente, cierra la puerta a la inyección de expresiones (ver §14) — pero **no valida el valor ni impone ningún predicado de titularidad**:

```java
// FileSearchMapper.java:21-46
for (WrapperMySearchFilterRequestSearchPropertiesInner prop : request.getSearchProperties()) {
    String field = mapField(keyId);                      // valida contra FileField
    Operator operator = mapOperator(keyOperator.name()); // valida contra RequestOperator {EQUAL, CONTAINS}
    Object value = castValue(keyId, prop.getKeyValue()); // <-- el valor no se valida
    ...
}
```

El operador `CONTAINS` se traduce a la función `contains()` de DynamoDB:

```java
// ExpressionBuilder.java:62-66
return switch (cond.operator) {
    case CONTAINS -> "contains(" + nameKey + ", " + valKey + ")";
    ...
};
```

En DynamoDB, `contains(attr, "")` es **verdadero para toda cadena**. Basta con enviar `keyValue: ""` sobre cualquier campo para que el filtro no filtre nada, y `BaseDynamoRepository.search()` recorre entonces la tabla completa — sin `Limit`, sin `LastEvaluatedKey`, sin cota:

```java
// BaseDynamoRepository.java:76-92
public List<T> search(FileSearch search) {
    ExpressionBuilder builder = new ExpressionBuilder();
    Expression expression = builder.build(search);
    ScanEnhancedRequest request = ScanEnhancedRequest.builder()
            .filterExpression(expression)     // el filtro se aplica DESPUES de leer todo
            .build();
    List<T> results = new ArrayList<>();
    table.scan(request).items().forEach(results::add);
    return results;
}
```

Y el mapeo de salida añade lo que convierte una fuga de metadatos en una fuga de datos personales:

```java
// DocumentMapper.java:44-55
wrapper.setDocumentId(objectSumary.getCustomerId());   // el id del documento
wrapper.setName(objectSumary.getName());               // <-- getName() es el ownerId: el DNI del titular
wrapper.setMimeType(objectSumary.getMimeType());
```

#### Flujo source → sink

```text
POST /v2/document_management/search_documents          (token Cognito valido; el gateway lo deja pasar)
   body: { "searchParameters": { "discriminator": "OR",
             "searchProperties": [ { "keyId": "NAME", "keyOperator": "CONTAINS", "keyValue": "" } ] } }
   ↓
DocumentManagementInputPort.postSearchDocuments()   — sin validador (los otros tres endpoints si lo tienen)
   ↓
FileSearchMapper.toSearch()                          — valida campo y operador, no el valor ni el titular
   ↓
ExpressionBuilder.build()                            — contains(#n0, "")  = siempre verdadero
   ↓
BaseDynamoRepository.search()                        — Scan de tabla completa, sin paginacion
   ↓
DocumentMapper.searchMapper()                        — name = DNI del titular
   ↓
200 OK con TODOS los documentos del sistema y el DNI de cada propietario
```

#### Escenario de explotación

Un usuario legítimo de la app móvil — o el proveedor del Ethical Hacking con las credenciales que se le entreguen — emite una única petición con `keyValue: ""`. Recibe el censo completo de documentos contractuales del sistema: identificador de documento, nombre y **DNI del titular** de cada uno. Con esa lista, cada `documentId` alimenta directamente `POST /download_document`, que devuelve una URL prefirmada de S3 válida durante diez minutos y **tampoco comprueba titularidad** (`DocumentManagementAdapter:62-72`).

La cadena completa — enumerar y luego descargar — está desarrollada en §8.

Ninguna capa del perímetro descrito en §1.2 interviene aquí: la petición está correctamente autenticada, es sintácticamente válida contra el contrato OpenAPI y su cuerpo no contiene ningún patrón que un WAF pueda marcar. Imperva, el WAF de AWS, Cognito y el API Gateway la dejan pasar porque no hay nada que objetar en ella.

#### Impacto

* **Protección de datos.** Exposición masiva de DNI asociados a documentación contractual. Es tratamiento de datos personales sin base de legitimación para el solicitante, notificable como incidente si se materializa.
* **Confidencialidad.** Acceso al inventario íntegro de documentos y, encadenado con `download_document`, a su contenido.
* **Disponibilidad y coste.** Cada llamada consume RCU proporcionales al tamaño total de la tabla, no al resultado devuelto. Sin rate limiting (SEC-019), unas pocas peticiones concurrentes agotan la capacidad aprovisionada o disparan el coste on-demand.

#### Remediación

```java
// Codigo vulnerable — DocumentManagementAdapter.java:80-97
FileSearch search = FileSearchMapper.toSearch(paramters);
var objectListing = repository.search(search);
return mapper.searchMapper(objectListing);
```

```java
// Codigo recomendado
@Override
public WrapperPostSearchDocumentsResponse searchDocuments(WrapperPostSearchDocumentsRequest criteria) {
  var params = criteria.getSearchParameters();
  searchValidator.validate(params);          // obligatorio: >=1 propiedad, valor no vacio, longitud minima

  // 1. El titular NO viene del cliente: se deriva del token (ver SEC-002)
  String ownerId = currentPrincipal().documentNumber();

  // 2. Consulta acotada por titular, no Scan. Requiere GSI por ownerId.
  FileSearch search = FileSearchMapper.toSearch(params).restrictedTo(ownerId);

  // 3. Paginacion explicita y tope duro
  var page = repository.queryByOwner(ownerId, search, PageRequest.of(criteria.getPage(), MAX_PAGE_SIZE));

  return mapper.searchMapper(page);          // 4. sin PII en la respuesta
}
```

```java
// DocumentMapper.searchMapper — dejar de devolver el DNI
wrapper.setName(objectSumary.getFileName());   // el nombre del fichero, no el ownerId
```

**El porqué.** Las tres correcciones son independientes y cada una por sí sola reduce el impacto, pero solo la primera lo elimina. Paginar limita el volumen por petición, no el total obtenible; quitar el DNI reduce la sensibilidad de lo expuesto, no el alcance. **Lo único que cierra el hallazgo es que el predicado de titularidad no sea negociable por el solicitante**, y eso exige que el identificador del titular venga del token y no del cuerpo de la petición.

Mientras SEC-002 no esté implementado, la mitigación inmediata y de bajo coste es **rechazar valores vacíos o de menos de tres caracteres** y **aplicar `Limit` al `ScanEnhancedRequest`**. No es una solución — sigue siendo posible barrer el espacio por prefijos — pero convierte un volcado de una petición en una campaña ruidosa y detectable.

---

## 6. Hallazgos de severidad Medium

Los siguientes hallazgos están confirmados en el código y documentados con su ubicación exacta. Se presentan de forma más concisa por su menor impacto individual; varios de ellos, sin embargo, contribuyen a las cadenas de ataque de la §7.

### SEC-024 — Cifrado AES sin autenticación y con transformación tomada de configuración

> ### ⏸️ APLAZADO en v1.7 (2026-09-03) — fuera del alcance de este Ethical Hacking
>
> Afecta solo a `cpe-nxhbsc-becustombeprogrm` (cifrado del payload hacia SKY), que no entra en el EH.
>
> **El hallazgo sigue siendo válido y sigue abierto.** No se ha corregido nada: el código permanece desplegado y el defecto es explotable por quien tenga acceso a ese componente. Lo único que cambia es que **no se mide contra este ejercicio** y no cuenta en los 47 hallazgos de alcance — sí en los 56 de deuda técnica. Se conserva íntegro, con su evidencia y su remediación, para que al volver a alcance recupere su historial en lugar de reaparecer como hallazgo nuevo.

**CWE-353 · becustombeprogrm · `AesEncryptionService.java:30-46, 61-67`**

```java
@SuppressWarnings("java:S5542")        // <-- supresión de la regla "cipher should be robust"
public String encrypt(String value){
    String transformation = resolveTransformation();   // p. ej. "AES" + "/CBC/PKCS5Padding"
    ...
    Cipher cipher = Cipher.getInstance(transformation);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
```

El IV se genera con `SecureRandom` y se antepone al texto cifrado — eso es correcto. El problema es que **AES/CBC no proporciona integridad**: el receptor no puede detectar si el texto cifrado fue manipulado, lo que abre la puerta a ataques de tipo padding oracle si el proveedor devuelve errores distinguibles (y de hecho `SKYServiceAdapter` distingue explícitamente el estado 406 como "Error de desencriptado", líneas 61-67 — exactamente el oráculo que ese ataque necesita).

Además, `resolveTransformation()` toma el modo de una propiedad externa, por lo que un cambio de configuración a `/ECB/PKCS5Padding` degradaría el cifrado sin cambio de código. La supresión `@SuppressWarnings("java:S5542")` oculta esta advertencia al análisis estático.

```java
// Código recomendado — AES-GCM (cifrado autenticado), transformación fija
private static final String TRANSFORMATION = "AES/GCM/NoPadding";
private static final int GCM_TAG_BITS = 128;
private static final int GCM_IV_BYTES = 12;

public String encrypt(String value) {
    byte[] iv = new byte[GCM_IV_BYTES];
    SecureRandom.getInstanceStrong().nextBytes(iv);

    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(GCM_TAG_BITS, iv));
    byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
    ...
}
```

Si el proveedor SKY impone AES/CBC, mantenerlo pero **añadir un HMAC-SHA256 sobre IV+ciphertext** con una clave distinta (encrypt-then-MAC), y eliminar la supresión de la regla dejando constancia del acuerdo con el proveedor.

### SEC-025 — Swagger UI y `/v3/api-docs` habilitados en todos los perfiles

**Severidad: Low** (rebajado desde Medium: el API Gateway no publica estas rutas) · **CWE-200 · todos · `application.yml`, `SecurityConfig`**

`springdoc.swagger-ui.path: /swagger-ui.html` esta definido en el `application.yml` base de los once proyectos, sin `springdoc.api-docs.enabled: false` en ningún perfil, y `SecurityConfig` lo declara `permitAll` de forma explícita. Desde el plano este-oeste, cualquier pod obtiene el contrato completo de los once servicios: rutas, esquemas y modelos de datos.

```yaml
# Recomendado — application-pro.yml / application-pre.yml / application-cert.yml
springdoc:
  api-docs:
    enabled: false
  swagger-ui:
    enabled: false
```

### SEC-026 — Cabeceras del consumidor alimentan el motor de decisión de riesgo

> ### ✅ Estado en v1.5 (re-verificado 2026-08-31) — **RESUELTO**
>
> El delegate ya no toca cabeceras. `CreditRiskDelegateImpl` se ha reducido a `validateCreditRisk(request)` y los parámetros globales se construyen con constantes de servidor:
>
> ```java
> // cpe-nxhbsc-becreditrisk/…/input/mapper/CreditRiskMapper.java:40-47
> return GlobalParameters.builder()
>         .application("App-Conexa")     // antes: cabecera del consumidor
>         .channel("scp")                // antes: cabecera del consumidor
>         .identifier(globalParameterRequest.getIdentifier())
>         …
> ```
>
> El campo `society` ha desaparecido de `GlobalParameters`. El vector concreto que describía este hallazgo —el consumidor eligiendo la sociedad y el canal con los que se evalúa su propio riesgo— ya no existe.
>
> **Residuo, para constancia y sin abrir hallazgo nuevo:** `identifier`, `identifierType`, `evaluationType` y `requestType` siguen llegando del cuerpo de la petición y siguen alimentando a Modellica. Son parámetros de la consulta, no de la política, así que el riesgo es cualitativamente menor; conviene aun así validarlos contra una lista cerrada de valores admitidos.


**CWE-807 · becreditrisk · `CreditRiskDelegateImpl.java:33-42`**

```java
var app = httpServletRequest.getHeader("society");
var channel = httpServletRequest.getHeader("channel");
var response = useCase.validateCreditRisk(
        mapper.toCreditRiskValidateCriteria(creditRiskValidateRequest, app, channel));
```

`society` y `channel` llegan sin validar desde el consumidor y forman parte de los `globalParameters` que se envían a Modellica. El solicitante declara en qué sociedad y por qué canal opera; si el motor de decisión aplica reglas distintas según esos valores —que es su propósito—, el solicitante influye en el resultado de la evaluación de riesgo.

```java
// Código recomendado
private static final Set<String> ALLOWED_SOCIETIES = Set.of("SCP", "BSP");
private static final Set<String> ALLOWED_CHANNELS  = Set.of("APP", "WEB", "OFICINA");

String society = require(httpServletRequest.getHeader("society"), ALLOWED_SOCIETIES, "society");
String channel = require(httpServletRequest.getHeader("channel"), ALLOWED_CHANNELS, "channel");
```

Preferible aún: derivar ambos valores de los claims del token de Cognito o del `client_id` registrado, no de cabeceras que el llamante controla.

### SEC-027 — `forward-headers-strategy: framework` con proxies encadenados

**CWE-348 · todos · `application.yml`** · Confianza: REQUIERE VALIDACIÓN

Los once servicios habilitan `server.forward-headers-strategy: framework`, lo que hace que Spring reconstruya el esquema, host y **IP de origen** a partir de `X-Forwarded-*`. La cadena tiene cinco saltos (Akamai → Imperva → WAF → API Gateway → PrivateLink → NLB), y no hay configuración de proxies de confianza. Si algún tramo no normaliza `X-Forwarded-For`, un valor inyectado por el cliente podría falsear la IP de origen registrada en los logs y en cualquier decisión basada en ella.

No se identificó ninguna lógica de negocio que dependa de la IP de origen, por lo que el impacto actual se limita a la trazabilidad. Verificar con el equipo de plataforma que Imperva y el API Gateway sobrescriben (no anexan) la cabecera, y considerar `ForwardedHeaderFilter` con lista de proxies de confianza.

### SEC-028 — Excepciones no controladas producen respuestas 500

**CWE-248 · 5 proyectos**

Ninguno de los `ControllerAdvice` declara un manejador para `Exception.class`; solo cubren `BusinessException`, `MethodArgumentNotValidException` y `HttpMessageNotReadableException`. `bedigitsignature` y `bedocmanagement` no tienen `ControllerAdvice` en absoluto. Puntos confirmados que lanzan excepciones no mapeadas con entrada controlada por el solicitante:

| Ubicación | Excepción | Disparador |
| --------- | --------- | ---------- |
| `bedigitsignature/DocumentProcessService.java:71` | `NoSuchElementException` | `.findFirst().get()` con `idDocumento` inexistente |
| `bedigitsignature/DocumentProcessService.java:49` | `NullPointerException` | `documentos` ausente (sin `required` en el contrato) |
| `beemailboxes/OTPServiceAdapter.java:105` | `NullPointerException` | `attachments` y `metadata` ambos nulos |
| `beemailboxes/OTPServiceAdapter.java:106` | `NumberFormatException` | `templateId` no numérico |
| `beemailboxes/OTPServiceAdapter.java:109` | `IndexOutOfBoundsException` | `flow` inexistente en la tabla |
| `becustombeprogrm/QurableServiceAdapter.java:169-177` | `IllegalArgumentException` | `benefit_program_id` distinto de `UP`/`DOWN` |
| `bedocmanagement/FileSearchMapper.java:51-76` | `IllegalArgumentException`, `NumberFormatException` | `keyId`/`keyValue` inválidos |

```java
// Código recomendado — .get() sustituido por control explícito
ApplicationSignDocumentRequestInner docItem = client.getDocumentos().stream()
        .filter(doc -> documentId.equals(doc.getIdDocumento()))
        .findFirst()
        .orElseThrow(() -> new BusinessException(HttpStatus.BAD_REQUEST, List.of(Exceptions.TL0002)));
```

```java
// Código recomendado — manejador de último recurso en cada ControllerAdvice
@ExceptionHandler(Exception.class)
public ResponseEntity<ErrorResponse> handleUnexpected(Exception ex) {
    String correlationId = UUID.randomUUID().toString();
    log.error("Error no controlado. correlationId={}", correlationId, ex);
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ErrorResponse.builder().errors(List.of(ErrorItem.builder()
                    .code(Exceptions.TL9999.getCode())
                    .message(Exceptions.TL9999.getMessage())
                    .level("error")
                    .description("Referencia: " + correlationId)     // sin detalle interno
                    .build())).build());
}
```

### SEC-029 — `ddl-auto: update` y `sql.init.mode: always` en producción

**CWE-16 · beproducoffering · `application-pro.yml`**

```yaml
jpa:
  hibernate:
    ddl-auto: update          # Hibernate modifica el esquema en producción
  defer-datasource-initialization: true
sql:
  init:
    mode: always              # ejecuta schema.sql/data.sql en cada arranque
```

`ddl-auto: update` permite que un cambio en una entidad Java altere el esquema de la base de datos productiva sin control de cambios ni revisión. `sql.init.mode: always` ejecuta scripts de inicialización en cada arranque. Los demás proyectos con RDS (`becreditrisk`) usan correctamente `validate`.

```yaml
# Recomendado
jpa:
  hibernate:
    ddl-auto: validate
sql:
  init:
    mode: never
```

Los cambios de esquema deben gestionarse con una herramienta de migración versionada (Liquibase/Flyway).

### SEC-030 — `patchConsent` nunca actualiza el consentimiento

> ### 🔴 Estado en v1.5 (re-verificado 2026-08-31) — **REMEDIACIÓN INCOMPLETA · el endpoint ahora falla siempre**
>
> Se intentó corregir y el intento empeoró el comportamiento observable. El método comprueba ahora que el consentimiento existe, pero **conserva `putIfAbsent` para la escritura**:
>
> ```java
> // cpe-nxhbsc-bedatacomanagment/…/jpa/DataConsentManagementAdapter.java:79-96
> Optional<ConsentEntity> entityList = consentRepository.getByKeyAndSk(partyId, consentId);
> if (entityList.isEmpty()) {                                    // ← añadido en este ciclo
>   throw new SantanderException("El consentimiento que intenta actualizar no existe");
> }
> consentRepository.putIfAbsent(mapper.toEntityUpdate(criteria, partyId, consentId));  // ← sin cambiar
> ```
>
> Y `putIfAbsent` es literalmente eso:
>
> ```java
> // …/config/BaseDynamoRepository.java:35-49
> String expr = "attribute_not_exists(" + partitionKeyAttr + ")";
> if (sortKeyAttr != null && !sortKeyAttr.isBlank())
>     expr += " AND attribute_not_exists(" + sortKeyAttr + ")";
> ```
>
> **Las dos ramas son ahora mutuamente excluyentes.** Si el consentimiento no existe, salta la excepción de la línea 83. Si existe —el único caso en que la operación tiene sentido— la condición `attribute_not_exists` falla, DynamoDB lanza `ConditionalCheckFailedException`, la captura el `catch (Exception e)` de la línea 92 y el cliente recibe **500 con `TL9999`**. No hay entrada que produzca una actualización correcta.
>
> El efecto neto es que revocar un consentimiento pasó de fallar en silencio a fallar con un error genérico. Para el cliente es igual de imposible; para el equipo, al menos ahora es visible. La corrección es sustituir la llamada por `table.updateItem(...)` o un `putItem` con condición `attribute_exists`.


**CWE-670 · bedatacomanagment · `DataConsentManagementAdapter.java:75-93`**

```java
Optional<ConsentEntity> entityList = consentRepository.getByKeyAndSk(partyId, consentId);
if (entityList.isEmpty()) {
    throw new SantanderException("El consentimiento que intenta actualizar no existe");
}
consentRepository.putIfAbsent(mapper.toEntityUpdate(criteria, partyId, consentId));   // <-- putIfAbsent
```

`putIfAbsent` aplica la condición `attribute_not_exists(id) AND attribute_not_exists(sk)`. Como el método acaba de comprobar que el registro **sí** existe, la escritura falla siempre con `ConditionalCheckFailedException`, capturada por el `catch (Exception)` y convertida en un 500 genérico. **La revocación o modificación de un consentimiento de tratamiento de datos nunca se persiste.**

Es un defecto funcional con consecuencia de cumplimiento directa: si un titular revoca su consentimiento, el sistema informa de un error y el consentimiento previo permanece vigente.

```java
// Código recomendado
consentRepository.update(mapper.toEntityUpdate(criteria, partyId, consentId));
```

```java
// BaseDynamoRepository — recomendado
public T update(T item) {
    return table.updateItem(UpdateItemEnhancedRequest.builder(itemClass)
            .item(item)
            .ignoreNulls(true)                       // actualización parcial
            .build());
}
```

### SEC-031 — El JWT se usa como clave primaria en DynamoDB

> ### ⏸️ APLAZADO en v1.7 (2026-09-03) — fuera del alcance de este Ethical Hacking
>
> El JWT se persiste para poder casar el **callback entrante** con su lote. Es mecanismo de recepción, que queda fuera del alcance en `bedigitsignature`.
>
> **El hallazgo sigue siendo válido y sigue abierto.** No se ha corregido nada: el código permanece desplegado y el defecto es explotable por quien tenga acceso a ese componente. Lo único que cambia es que **no se mide contra este ejercicio** y no cuenta en los 47 hallazgos de alcance — sí en los 56 de deuda técnica. Se conserva íntegro, con su evidencia y su remediación, para que al volver a alcance recupere su historial en lugar de reaparecer como hallazgo nuevo.

**CWE-522 · bedigitsignature · `Entity.java:53-73`, `DocumentProcessService.java:107`**

```java
@DynamoDbBean
public class Entity {
    private String jwt;
    ...
    @DynamoDbPartitionKey
    @DynamoDbAttribute("documentNumber")      // <-- el atributo se llama "documentNumber"
    public String getJwt() { return jwt; }
```

Un token de autenticación se almacena en claro como clave de partición. Las claves primarias aparecen en índices, en backups, en exportaciones a S3, en `Contributor Insights` y en las métricas de claves calientes de DynamoDB — todos ellos lugares donde un secreto no debería estar. Además, el atributo se denomina `documentNumber`, lo que induce a error a cualquiera que consulte la tabla o construya una consulta sobre ella.

```java
// Código recomendado
@DynamoDbBean
public class SignatureBatchEntity {
    private String loteId;
    private String documentId;
    private String jwtId;        // solo el 'jti', no el token
    private String estado;
    private Instant createdAt;
    private Long ttl;            // expiración automática

    @DynamoDbPartitionKey
    @DynamoDbAttribute("loteId")
    public String getLoteId() { return loteId; }

    @DynamoDbSortKey
    @DynamoDbAttribute("documentId")
    public String getDocumentId() { return documentId; }
}
```

El callback debe localizar el lote por `loteId` (obtenido del `sub` del token que él mismo presenta y valida), no por el token almacenado.

### SEC-032 — Código de prueba activo en la ruta productiva

**CWE-489 · bedigitsignature · `DocumentClient.java:34-46`**

```java
public Mono<String> getDocument(String documentId) {
    log.info("antes en obtener document, documentId: {}", documentId);
    if(documentId.equals("CONTRATO_CLIENTE")){
        try {
            ClassPathResource resource = new ClassPathResource("test.pdf");
            byte[] pdfBytes = resource.getInputStream().readAllBytes();
            String fileBase64 = Base64.getEncoder().encodeToString(pdfBytes);
            return Mono.just(fileBase64);
        } catch (Exception ex){ return Mono.empty(); }
    }
    ...
```

Un valor mágico en la entrada desvía el flujo a un documento empaquetado en el JAR, evitando por completo la consulta a `bedocmanagement`. Permite enviar a firmar un PDF de pruebas como si fuera un contrato real. Además, `documentId.equals(...)` lanza `NullPointerException` si el valor es nulo (SEC-028).

```java
// Código recomendado
public Mono<String> getDocument(String documentId) {
    Objects.requireNonNull(documentId, "documentId es obligatorio");
    return documentWebClient.post()
            .uri(Constant.POST_DOCUMENT)
            ...
}
```

El caso de prueba debe cubrirse con un stub en los tests (WireMock/MockWebServer), no con una rama condicional en el adaptador productivo. Retirar también `test.pdf` de `src/main/resources`.

### SEC-033 — Token cacheado indefinidamente y sin renovación

**CWE-613 · beclaims · `TokenService.java:31-67`**

```java
private String cachedToken;

public String getToken(){
    if(cachedToken == null) {          // <-- única condición de renovación
        refreshToken();
    }
    return cachedToken;
}

private synchronized void refreshToken(){
    if(cachedToken!= null){ return; }
    var authRequest = buildAuthRequest();
    log.warn("authRequest: {}", authRequest.toString());          // SEC-007

    var response = tokenWebClient.post()
            ...
            .bodyValue(buildAuthRequest())     // <-- se construye por segunda vez
            ...
```

El token se obtiene una vez y no se renueva nunca mientras viva el pod. Cuando el token expire en el proveedor, todas las llamadas devolverán 401 — que, por SEC-010, se convierten en respuestas mock exitosas, ocultando el fallo por completo. `becreditrisk` y `bewatchscreening` sí gestionan la expiración; `beclaims` no.

Detalle adicional: `buildAuthRequest()` se invoca dos veces (líneas 49 y 55), lo que evidencia que el registro de la línea 50 se añadió para depuración y quedó en el código.

```java
// Código recomendado — alineado con becreditrisk
private volatile CachedToken cachedToken;

public String getToken() {
    if (isTokenValid()) return cachedToken.getAccessToken();
    refreshToken();
    return cachedToken.getAccessToken();
}

private synchronized void refreshToken() {
    if (isTokenValid()) return;
    var authRequest = buildAuthRequest();                          // una sola vez
    var response = tokenWebClient.post().uri(Constant.POST_TOKEN)
            .bodyValue(authRequest)
            ...
            .block();
    if (response == null || response.getToken() == null) {
        throw new ClaimsValidationException(Constant.MESSAGE_INVALID_CREDENTIALS);
    }
    cachedToken = new CachedToken(response.getToken(),
                                  Instant.now().plusSeconds(TOKEN_TTL_SECONDS - 30));
}

private boolean isTokenValid() {
    return cachedToken != null && Instant.now().isBefore(cachedToken.getExpirationTime());
}
```

### SEC-034 — Deriva de versiones y mezcla de majors incompatibles

> ### 🔺 Estado en v1.5 (re-verificado 2026-08-31) — **AGRAVADO**
>
> La mezcla de líneas de Netty ya no está aislada en `bedatacomanagment`; ahora también está en `beclaims`:
>
> | Proyecto | Artefactos 4.1.x | Artefactos 4.2.x |
> | -------- | ---------------- | ---------------- |
> | `beclaims` | `netty-codec-dns`, `netty-resolver-dns`, `netty-handler` **4.1.135** | `netty-codec-http`, `netty-codec-http2`, `netty-transport-native-epoll` **4.2.13** |
> | `bedatacomanagment` | `netty-handler`, `netty-resolver-dns` **4.1.135** | `netty-codec-dns`, `netty-transport-native-epoll` **4.2.13**, y `<netty.version>` **4.2.16** |
>
> Mezclar `4.1.x` y `4.2.x` del mismo framework en un mismo classpath no es deriva de versiones: es una combinación no soportada. Se manifiesta como `NoSuchMethodError` o `LinkageError` en ejecución, no en compilación, lo que la hace especialmente difícil de detectar antes de producción.
>
> La deriva del parent corporativo también persiste: `1.5.0` (`beemailsend`), `1.5.1` (`beproducoffering`), `1.5.2` (cuatro proyectos) y `1.6.0` (cinco). Y `bedigitsignature` fija `jackson-core:2.21.4` sin alinear `jackson-databind`.


**CWE-1104 · todos · `pom.xml`**

Ver el detalle en la seccion 12 (Dependency Security Review). Resumen: tres versiones distintas del parent corporativo (1.5.1, 1.5.2, 1.6.0), tres de Jackson (2.18.8, 2.21.4, 2.21.5), tres de Netty (4.1.135, 4.1.136, 4.2.13) y dos de AWS SDK STS (2.40.13, 2.42.33) conviviendo entre proyectos del mismo dominio.

El caso con riesgo tecnico inmediato es `bedatacomanagment`, que combina **dos lineas mayores de Netty en el mismo artefacto**: `netty-handler` y `netty-resolver-dns` en 4.1.135.Final junto a `netty-codec-http`, `netty-codec-http2` y `netty-transport-native-epoll` en 4.2.13.Final. Netty no garantiza compatibilidad binaria entre 4.1.x y 4.2.x, por lo que la combinacion puede producir `NoSuchMethodError` en tiempo de ejecucion.

### SEC-035 — `assert` usado para control de flujo

**CWE-617 · beemailboxes · `JsonTokenProvider.java:56`, `XmlTokenProvider.java:116`**

```java
ResponseEntity<OTPTokenResponse> response = restTemplate.postForEntity(...);
OTPTokenResponse data = response.getBody();

assert data != null;                       // <-- inactivo salvo con -ea
cachedToken = data.getData().getAccessToken();
```

Las aserciones de Java están **desactivadas por defecto** en tiempo de ejecución. La comprobación no se ejecuta y la línea siguiente produce `NullPointerException`, que se propaga hasta un 500 (SEC-028). El código transmite una garantía que no existe.

```java
// Código recomendado
OTPTokenResponse data = response.getBody();
if (data == null || data.getData() == null) {
    throw new BusinessException(HttpStatus.BAD_GATEWAY, List.of(Exceptions.TL9999));
}
```

### SEC-036 — `XmlMapper` sin endurecimiento explícito

**CWE-611 · beemailboxes · `XmlApiClient.java:31, 124`** · Confianza: REQUIERE VALIDACIÓN

```java
private final XmlMapper xmlMapper = new XmlMapper();
...
ResponseOTP responseOTP = xmlMapper.readValue(response.getBody(), ResponseOTP.class);
```

Se deserializa XML procedente del proveedor de correo sin configurar explícitamente el parser. Las versiones actuales de Woodstox —el backend por defecto de `jackson-dataformat-xml`— deshabilitan las entidades externas por defecto, por lo que **no se confirma explotabilidad**; pero la configuración depende de la biblioteca subyacente y no del código, lo que la hace frágil ante cambios de dependencia. Dado que la respuesta del proveedor es una entrada no confiable (SEC-004 permite además su manipulación en tránsito), conviene fijarlo explícitamente:

```java
// Código recomendado
private static XmlMapper hardenedXmlMapper() {
    XMLInputFactory factory = XMLInputFactory.newFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    return new XmlMapper(new XmlFactory(factory));
}
```

Declarar además el bean como singleton de Spring en lugar de instanciarlo por componente.

### SEC-037 — Ausencia de idempotencia y de protección anti-replay

**CWE-799 · bedigitsignature, becustombeprogrm, beemailboxes**

Ninguna operación de escritura acepta una clave de idempotencia, y ninguna incorpora `timestamp`, `nonce` o identificador de petición para detectar reenvíos. Operaciones afectadas y su efecto ante un reenvío:

| Operación | Efecto de la repetición |
| --------- | ----------------------- |
| `POST /v1/signature/signer` | Nuevo `loteId` y nueva solicitud de firma al proveedor por cada llamada |
| `POST /register_customer` | Alta duplicada en SKY (agravado por el retry, SEC-017) |
| `POST /{emailbox_id}/send_email` | Nuevo OTP y nuevo correo en cada llamada |
| `POST /consent_relationships` | Consentimiento duplicado con nuevo UUID |

```java
// Código recomendado — patrón general
public ApplicationSignatureResponse signtureDocument(ApplicationSignatureRequest request,
                                                     String idempotencyKey) {
    Optional<StoredResponse> previous = idempotencyStore.find(idempotencyKey);
    if (previous.isPresent()) {
        return previous.get().response();          // misma respuesta, sin repetir el efecto
    }
    ApplicationSignatureResponse response = doSign(request);
    idempotencyStore.save(idempotencyKey, response, Duration.ofHours(24));
    return response;
}
```

Declarar `Idempotency-Key` como cabecera requerida en los contratos de las operaciones de escritura, y usar el TTL nativo de DynamoDB para la tabla de idempotencia.

### SEC-038 — Datos externos escritos en el log sin neutralizar

**CWE-117 · 6 proyectos** · Confianza: REQUIERE VALIDACIÓN

Valores controlados por el solicitante se interpolan directamente en mensajes de log:

```java
bedigitsignature/DocumentClient.java:36      log.info("antes en obtener document, documentId: {}", documentId);
becustombeprogrm/AltaUsuarioService.java:36  log.info("Iniciando alta de usuario. documentNumber={}", documentNumber);
becustombeprogrm/QurableServiceAdapter.java:158  log.info("Usuario no encontrado en Qurable. documentNumber={}", documentNumber);
```

Si un valor contiene `\n` o `\r`, puede inyectar líneas falsas en el log. El formato configurado es `GLUONLOG`, que serializa a JSON y previsiblemente escapa los caracteres de control — de ahí la clasificación como *requiere validación*. Debe confirmarse con el equipo del framework; si el escape no está garantizado, sanear en origen:

```java
// Código recomendado
private static String safe(String value) {
    return value == null ? "null" : value.replaceAll("[\\r\\n\\t]", "_");
}
log.info("Obteniendo documento. documentId={}", safe(documentId));
```

Nota adicional: varios de estos registros escriben el número de documento del cliente en nivel `INFO`. Aun sin inyección, es dato personal en logs con retención prolongada; conviene enmascararlo (`****5678`).

### SEC-039 — `search_documents` ejecuta un Scan completo de DynamoDB

**CWE-405 · bedocmanagement · `BaseDynamoRepository.java:76-92`, `DocumentManagementAdapter.java:79-96`**

```java
public List<T> search(FileSearch search) {
    ExpressionBuilder builder = new ExpressionBuilder();
    Expression expression = builder.build(search);

    ScanEnhancedRequest request = ScanEnhancedRequest.builder()
            .filterExpression(expression)      // <-- filtro, no condición de clave
            .build();
    ...
}
```

En DynamoDB, `filterExpression` se aplica **después** de leer los elementos: el `Scan` recorre la tabla completa y consume capacidad por todo lo leído, no por lo devuelto. Sin paginación ni `Limit`, cada búsqueda es una lectura íntegra de la tabla de documentos. Combinado con la ausencia de autorización (SEC-002), permite además localizar documentos de cualquier titular.

**Aspecto positivo confirmado:** `ExpressionBuilder` construye la expresión con marcadores (`#n0`, `:v0`) y `expressionNames`/`expressionValues`, y `FileSearchMapper.mapField` valida el campo contra el enum `FileField`. **No existe inyección de expresión** — es una implementación correcta y merece señalarse como control existente (§13).

```java
// Código recomendado — índice secundario global + consulta acotada
public List<T> searchByOwner(String ownerId, FileSearch search, int limit, Map<String, AttributeValue> startKey) {
    return table.index("owner-index")
            .query(QueryEnhancedRequest.builder()
                    .queryConditional(QueryConditional.keyEqualTo(
                            Key.builder().partitionValue(ownerId).build()))
                    .filterExpression(new ExpressionBuilder().build(search))
                    .limit(limit)
                    .exclusiveStartKey(startKey)
                    .build())
            .stream().flatMap(p -> p.items().stream()).toList();
}
```

### SEC-040 — La respuesta de watchlist screening indica siempre "Match Found"

**CWE-393 · bewatchscreening · `GesintelAdapter.java:100-115`**

```java
private static WatchListResolutionResponse buildResponse(String codeResponse) {
    String description = Constant.CODES_RESPONSE.getOrDefault(codeResponse, Constant.MESSAGE_CODE_NOT_FOUND);
    return WatchListResolutionResponse.builder()
            .validationResult(ValidationResult.builder()
                    .result(Constant.MESSAGE_MATCH_FOUND)      // <-- constante: siempre "Match Found"
                    .build())
            .antiMoneyLaundering(...riskSourceCode(codeResponse)...)
            .build();
}
```

`buildResponse` se invoca tanto cuando hay coincidencias (`CODE_RESPONSE_0` = "bloqueados") como cuando no las hay (`CODE_RESPONSE_1` = "sin observacion"), y en ambos casos fija `validationResult.result` a `"Match Found"`. La distinción real solo aparece en `riskSourceCode`.

Un consumidor que lea el campo `result` —el nombre sugiere que es el veredicto— concluirá que **toda persona consultada tiene coincidencia en listas AML**. En un proceso de onboarding esto se traduce en falsos positivos sistemáticos o, si el consumidor ignora el campo por poco fiable, en la pérdida de una señal de control.

```java
// Código recomendado
private static WatchListResolutionResponse buildResponse(String codeResponse) {
    boolean hasMatch = Constant.CODE_RESPONSE_0.equals(codeResponse)
                    || Constant.CODE_RESPONSE_2.equals(codeResponse);
    return WatchListResolutionResponse.builder()
            .validationResult(ValidationResult.builder()
                    .result(hasMatch ? Constant.MESSAGE_MATCH_FOUND : Constant.MESSAGE_NO_MATCH)
                    .build())
            ...
}
```

Confirmar la semántica esperada con el equipo funcional y con Gesintel antes de aplicar el cambio, ya que consumidores existentes pueden haberse adaptado al comportamiento actual.

---

### SEC-050 — El path variable determina el verbo HTTP hacia el proveedor

> ### ⏸️ APLAZADO en v1.7 (2026-09-03) — fuera del alcance de este Ethical Hacking
>
> Afecta solo a `cpe-nxhbsc-becustombeprogrm` (verbo HTTP hacia Qurable), que no entra en el EH.
>
> **El hallazgo sigue siendo válido y sigue abierto.** No se ha corregido nada: el código permanece desplegado y el defecto es explotable por quien tenga acceso a ese componente. Lo único que cambia es que **no se mide contra este ejercicio** y no cuenta en los 47 hallazgos de alcance — sí en los 56 de deuda técnica. Se conserva íntegro, con su evidencia y su remediación, para que al volver a alcance recupere su historial en lugar de reaparecer como hallazgo nuevo.

**CWE-470 · becustombeprogrm · `QurableServiceAdapter.java:80-92, 169-178`**

```java
public WrapperTier updateTiers(String action, UpdateTierRequest updateTierRequest) {
    HttpMethod method = resolveHttpMethod(action);      // action = {benefit_program_id}
    ...
    webClient.method(method).uri(Constant.URI_API_SKY_TIER)

private HttpMethod resolveHttpMethod(String action) {
    return switch (action) {
        case "UP"   -> HttpMethod.PATCH;
        case "DOWN" -> HttpMethod.DELETE;
        default -> throw new IllegalArgumentException("Acción inválida: " + action);
    };
}
```

El path variable `{benefit_program_id}` de `PATCH /categories/{benefit_program_id}` no identifica un recurso: **selecciona el método HTTP** que se ejecutará contra el proveedor Qurable, incluido `DELETE`.

Hoy el conjunto está acotado a dos valores y no es explotable más allá de provocar un 500 con cualquier otro (`IllegalArgumentException` sin manejador, ver SEC-028). El riesgo es de diseño: un parámetro controlado por el consumidor gobierna la semántica de una llamada saliente destructiva, y basta con añadir un caso al `switch` para que pase a serlo.

Un revisor externo lo marcará aunque hoy esté acotado, porque el patrón es el que precede a las vulnerabilidades de este tipo.

```java
// Código recomendado — la acción es parte del contrato, no del identificador
public WrapperTier updateTiers(String benefitProgramId, UpdateTierRequest request) {
    HttpMethod method = switch (request.getAction()) {          // enum del contrato
        case UP   -> HttpMethod.PATCH;
        case DOWN -> HttpMethod.DELETE;
    };
    ...
}
```

Si el contrato no puede cambiarse, mantener el `switch` pero validar antes con un enum y devolver `400` con código `TL*` en lugar de propagar `IllegalArgumentException`.

### SEC-051 — Campos cruzados en `FileEntity`: `customerId` no contiene el cliente

**CWE-1109 · bedocmanagement · `FileEntity.java:18-36`, `DocumentMapper.java:71-90`**

Los nombres de los campos no corresponden con lo que almacenan:

| Campo Java | Atributo DynamoDB | Contenido real |
|---|---|---|
| `customerId` | `id` (partition key) | **UUID del documento** (`entity.setCustomerId(documentId)`) |
| `name` | `filename` (sort key) | **`ownerId` del titular** |
| `fileName` | — | Nombre real del fichero |

```java
// DocumentManagementAdapter.java:107,132
String documentId = UUID.randomUUID().toString();
FileEntity entity = mapper.toEntity(criteria, documentId, key);

// DocumentMapper.java:81,84,88
entity.setName(documentRequest.getOwners().get(0).getOwnerId());   // titular -> name
entity.setFileName(documentRequest.getName());                     // fichero -> fileName
entity.setCustomerId(id);                                          // documentId -> customerId
```

No es explotable por sí solo, pero es una **trampa activa** para la remediación de SEC-002: lo natural al implementar la comprobación de titularidad es compararla contra `customerId`, y eso no valida nada — compararía el identificador del documento consigo mismo, dando siempre acceso.

La comprobación debe hacerse contra `name`. Se documenta como hallazgo propio precisamente porque induce a error: durante esta revisión se interpretó mal en una primera lectura, y la recomendación tuvo que corregirse.

```java
// Código recomendado — renombrar para que el modelo diga lo que guarda
@DynamoDbBean
public class FileEntity {
    private String documentId;    // era customerId  (partition key "id")
    private String ownerId;       // era name        (sort key "filename")
    private String fileName;
    ...
    @DynamoDbPartitionKey @DynamoDbAttribute("id")
    public String getDocumentId() { return documentId; }

    @DynamoDbSortKey @DynamoDbAttribute("filename")
    public String getOwnerId() { return ownerId; }
}
```

Los `@DynamoDbAttribute` mantienen los nombres físicos, por lo que **el renombrado no exige migrar datos**. Es refactor de código, no de esquema.

---

### SEC-056 — Valores de relleno como defecto de variables de entorno en perfiles `pre` y `pro`

> ### 🔴 Estado en v1.6 (re-verificado 2026-09-03) — **AGRAVADO · Medium → High**
>
> `bedigitsignature` **ha eliminado sus cuatro ficheros de perfil** — `application-local.yml`, `application-cert.yml`, `application-pre.yml` y `application-pro.yml` — y ha consolidado todo en un único `application.yml`. Es el único de los once servicios sin separación de configuración por entorno (`beemailsend`, la plantilla, tampoco la tiene, pero no despliega nada).
>
> El problema no es la consolidación en sí, sino **lo que ese fichero único contiene**:
>
> ```yaml
> # cpe-nxhbsc-bedigitsignature/src/main/resources/config/application.yml:57-76
> jwt:
>   secret: ${SEC_SKY_JWT_SECRET:12}          # <-- clave de firma HMAC por defecto: "12"
> aws:
>   bucket: ${AWS_BUCKET01_NAME:xx}
>   dynamodb:
>     role-arn: ${AWS_IRSA_BEDOCMANAGEMENT:test}   # <-- rol de OTRO servicio (SEC-054) + relleno
>   region: ${AWS_TABLE_REGION:xx}
>   table:  ${AWS_TABLE14_NAME:xx}
> proxy:
>   host: ${PROXY_HOST:1}
>   port: ${PROXY_PORT:1}
> clients:
>   document:
>     x-santander-client-id: 123               # <-- literal, sin variable
> ```
>
> Antes estos rellenos vivían en perfiles no productivos; **ahora son los valores por defecto de producción**. Si una variable no se inyecta en el despliegue, el servicio no falla al arrancar: arranca con el relleno. Dos consecuencias concretas:
>
> * `jwt.secret = "12"` produce una clave HMAC de 2 bytes. `Keys.hmacShaKeyFor` la rechaza con `WeakKeyException` para HS256, de modo que el fallo sería ruidoso — pero cualquier valor de más de 32 bytes puesto «para probar» pasaría silenciosamente y firmaría los JWT reales del flujo de firma digital.
> * `region: xx` y `table: xx` hacen que el cliente de DynamoDB apunte a una región inexistente: fallo en la primera escritura, no en el arranque, es decir **en mitad de una operación de firma**.
>
> Se eleva a High porque deja de ser higiene de configuración y pasa a ser exposición productiva: un despliegue con una variable olvidada arranca con material criptográfico de relleno en lugar de negarse a arrancar.
>
> En los demás proyectos el patrón **persiste sin cambios**. `bedocmanagement/application-pro.yml` sigue con `bucket`, `region` y `table` a `xx` y `role-arn` a `test`; `beemailboxes/application-pro.yml` mantiene `role-arn: ${AWS_IRSA_BEEMAILBOXES:test}`.
>
> **Remediación:** eliminar todo valor por defecto en `pre`, `pro` y `cert`. `${VAR}` sin defecto hace que Spring falle en el arranque, que es exactamente el comportamiento deseado: un despliegue mal configurado no debe llegar a servir tráfico. Y restaurar los perfiles de `bedigitsignature`.

**Severidad:** ~~Medium~~ **High** · **Confianza:** CONFIRMADO · **Prioridad:** ~~P2~~ **P1**
**CWE:** CWE-453 (Insecure Default Variable Initialization), CWE-1188
**OWASP:** API8:2023 Security Misconfiguration
**Proyecto/API:** bedocmanagement, bedatacomanagment, becustombeprogrm, bedigitsignature
**Nuevo en v1.5.** Efecto colateral de la externalización de secretos de SEC-003.

#### Ubicación y evidencia

La externalización a `${SEC_*}` se hizo, en varios sitios, dejando un valor por defecto de relleno. En el perfil `local` es razonable; en `pre`, `pro` y en los ficheros base, no:

```yaml
# cpe-nxhbsc-bedocmanagement/src/main/resources/config/application-pro.yml:2-7
aws:
  bucket: ${AWS_BUCKET01_NAME:xx}
  dynamodb:
    role-arn: ${AWS_IRSA_BEDOCMANAGEMENT:test}
  region: ${AWS_TABLE_REGION:xx}
  table: ${AWS_TABLE04_NAME:xx}

# cpe-nxhbsc-bedatacomanagment/src/main/resources/config/application-pro.yml:3-5
    role-arn: ${AWS_IRSA_BEDATACOMANAGMENT:test}
    region:   ${AWS_TABLE_REGION:1}
    table:    ${AWS_TABLE01_NAME:123}

# cpe-nxhbsc-becustombeprogrm/src/main/resources/config/application-pro.yml:32,34
  region:   ${AWS_TABLE_REGION:us-east-1}
  role-arn: ${AWS_IRSA_BEEMAILBOXES:test}

# cpe-nxhbsc-bedigitsignature/src/main/resources/config/application.yml:58-69  ← fichero BASE: aplica a los 4 perfiles
jwt:
  secret: ${SEC_SKY_JWT_SECRET:12}
aws:
  bucket:   ${AWS_BUCKET01_NAME:xx}
  dynamodb:
    role-arn: ${AWS_IRSA_BEDOCMANAGEMENT:test}
  region:   ${AWS_TABLE_REGION:xx}
  table:    ${AWS_TABLE14_NAME:xx}
proxy:
  host: ${PROXY_HOST:1}
  port: ${PROXY_PORT:1}
```

#### Descripción

Un `${VAR}` sin defecto hace que Spring falle al arrancar si la variable no está: el despliegue se cae, alguien lo mira y lo arregla. Un `${VAR:xx}` hace lo contrario — **el servicio arranca con una configuración falsa** y el fallo aparece más tarde, en la primera petición real, con un error que no señala su causa.

Los efectos concretos, por gravedad:

| Defecto | Efecto si la variable no se inyecta |
| ------- | ----------------------------------- |
| `SEC_SKY_JWT_SECRET:12` | Clave HMAC de 2 bytes para HS256, muy por debajo del mínimo de 256 bits. Con jjwt salta `WeakKeyException` en ejecución; si en el futuro se cambia de librería o de algoritmo, la firma pasa a ser trivialmente falsificable. Es el defecto más peligroso del bloque porque es una **clave criptográfica**, y vive en el fichero **base**, no en un perfil |
| `AWS_IRSA_*:test` | `AssumeRole` contra un ARN inválido: el servicio arranca, la primera operación contra DynamoDB o S3 falla con un error de STS que no menciona la configuración |
| `AWS_BUCKET01_NAME:xx`, `AWS_TABLE*_NAME:xx` | Operaciones contra un bucket o tabla inexistentes. En el mejor caso `NoSuchBucket`; en el peor, contra un recurso llamado `xx` que exista por accidente en la cuenta |
| `AWS_TABLE_REGION:us-east-1` | El servicio opera silenciosamente contra **otra región**, en un despliegue que se supone regional. No da error: da un recurso vacío |
| `PROXY_HOST:1` | Salida a terceros a través de un proxy inexistente |

La comprobación cruzada con los manifiestos lo hace concreto: el `values-pro.yaml` de `becustombeprogrm` declara cinco `extraEnvVars`, y **ninguna** es `AWS_IRSA_*`, `AWS_TABLE_REGION` ni `AWS_TABLE14_NAME`. O esas variables llegan por otra vía no visible en el repositorio, o los defectos están activos hoy en producción.

#### Remediación

```yaml
# En pre/pro y en los ficheros base: sin defecto. Que falle al arrancar es la funcionalidad.
aws:
  bucket:   ${AWS_BUCKET01_NAME}
  dynamodb:
    role-arn: ${AWS_IRSA_BEDOCMANAGEMENT}
  region:   ${AWS_TABLE_REGION}
  table:    ${AWS_TABLE04_NAME}
jwt:
  secret:   ${SEC_SKY_JWT_SECRET}
```

Los defectos de conveniencia pertenecen a `application-local.yml`, y solo con valores que no sean credenciales.

**El porqué.** En configuración de producción, *fail fast* es una propiedad de seguridad, no una molestia. Un arranque que falla se detecta en el despliegue y no llega a atender tráfico; un arranque que triunfa con valores falsos atiende peticiones y falla de forma difusa, a veces horas después y con un mensaje que apunta a AWS en lugar de al chart. Para reforzarlo, `@ConfigurationProperties` con `@Validated` y `@NotBlank` en cada campo obligatorio convierte el fallo en un mensaje que nombra la propiedad que falta.

---

### SEC-059 — La tabla de auditoría biométrica almacena DNI y tokens de sesión en claro, sin TTL

**Severidad:** Medium · **Confianza:** CONFIRMADO · **Prioridad:** P2
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information), CWE-359 (Exposure of Private Personal Information)
**OWASP:** API3:2023 Broken Object Property Level Authorization · API8:2023
**Proyecto/API:** cpe-nxhbsc-beidentbiometric
**Nuevo en v1.6.**

#### Ubicación

```text
Archivo: cpe-nxhbsc-beidentbiometric/src/main/java/.../application/ports/input/BiometricInputPort.java
Metodos: buildWrapperLogApiBiometric(...)  · lineas 369-392
         toJson(Map) / cleanData(Object)   · lineas 394-415
Archivo: .../infrastructure/adapters/output/client/rest/FacephiAdapter.java · buildWrapperExecution, lineas 333-347
Archivo: .../infrastructure/adapters/output/jpa/data/LogApiBiometric.java   · lineas 73-91
```

#### Descripción

Las **catorce** operaciones de `BiometricInputPort` persisten en DynamoDB una copia del request y del response intercambiados con FacePhi:

```java
// BiometricInputPort.java:382-391
return WrapperLogApiBiometric.builder()
    .requestId(requestId)
    .methodCode(methodCode)
    .requestBody(toJson(request))       // <-- copia del request enviado a FacePhi
    .responseBody(toJson(response))     // <-- copia de la respuesta
    .timestamp(Instant.now())
    .status(status)
    .build();
```

**Existe un control, y es correcto hasta donde llega.** `cleanData` recorre el mapa y sustituye toda cadena de más de 500 caracteres:

```java
// BiometricInputPort.java:407-412
if (str.length() > MAX_STRING_LENGTH) {
    // TODO guardar en S3
    return "[Content removed]";
}
return str;
```

Eso saca de la tabla lo más voluminoso y lo más sensible: `image`, `imageBuffer`, `templateRaw`, `registeredTemplateRaw` y los tokens de imagen — es decir, **las plantillas faciales no se almacenan**. Es un control real y conviene reconocerlo.

**El problema es el criterio.** El umbral es la *longitud*, no la *sensibilidad*, y por debajo de 500 caracteres queda en claro exactamente lo que identifica a una persona:

| Campo | DTO de origen | Longitud típica | ¿Se almacena? |
| ----- | ------------- | --------------- | ------------- |
| `documentNumber` (DNI) | `FacephiCivilValidationFacialRequest` | 8 | **Sí** |
| `userId` | `FacephiAuthenticateUserRequest`, `FacephiUserTemplateRequest` | ~36 (UUID) | **Sí** |
| `merchantReferenceId` | `FacephiAuthenticateUserRequest` | corto | **Sí** |
| `tokenOcr` | `FacephiExtractDocumentDataRequest` | variable | **Sí si ≤500** |
| `scanReference` | respuesta de `documentValidationStart` | ~36 | **Sí** |
| `templateRaw`, `image`, `imageBuffer` | varios | miles | No (truncados) |

`LogApiBiometric` no declara **ningún atributo TTL**, de modo que estos registros se acumulan indefinidamente: el resultado es un histórico permanente que asocia DNI, identificador de usuario y referencia de escaneo por cada intento de onboarding o autenticación biométrica del sistema.

El comentario `// TODO guardar en S3` indica que el diseño previsto era mover el contenido a S3 en lugar de descartarlo. Conviene resolverlo antes de implementarlo: **hacerlo tal cual reintroduciría el almacenamiento de plantillas faciales**, esta vez en un bucket, que es un dato biométrico de categoría especial.

#### Impacto

El acceso a esta tabla no requiere pasar por la API: cualquier principal con permiso de lectura sobre ella — y ahí entra el rol IAM del pod, que otros servicios asumen indebidamente según **SEC-054** — obtiene el histórico completo de identidades procesadas. No es una vía de explotación desde el exterior, sino una **ampliación del radio de impacto** de cualquier compromiso de credenciales AWS o de movimiento lateral dentro del VPC.

#### Remediación

```java
// Codigo recomendado — clasificar por sensibilidad, no por longitud
private static final Set<String> CAMPOS_SENSIBLES = Set.of(
    "documentNumber", "userId", "tokenOcr", "token1", "token2",
    "bestImageToken", "templateRaw", "image", "imageBuffer", "merchantReferenceId");

private Object cleanData(String key, Object value) {
    if (CAMPOS_SENSIBLES.contains(key)) {
        return "[REDACTED]";                       // o un hash con sal si se necesita correlacionar
    }
    if (value instanceof String str && str.length() > MAX_STRING_LENGTH) {
        return "[Content removed]";
    }
    ...
}
```

Y en la entidad:

```java
// LogApiBiometric — anadir expiracion automatica
@DynamoDbAttribute("ttl")
public Long getTtl() {   // epoch seconds; habilitar TTL en la tabla
    return ttl;          // p.ej. Instant.now().plus(90, DAYS).getEpochSecond()
}
```

**El porqué.** Una traza de auditoría necesita saber *qué operación se hizo, cuándo y con qué resultado*; no necesita el contenido de la petición. Sustituir los identificadores personales por un hash con sal conserva la capacidad de correlacionar intentos del mismo sujeto — que es para lo que sirve esta tabla — sin conservar el dato. Y el TTL no es higiene: es minimización, y es lo que acota la ventana de exposición de un compromiso futuro a los últimos 90 días en lugar de a toda la historia del sistema.

---

## 7. Hallazgos de severidad Low e informativos

### SEC-041 — Generador de códigos con PRNG no criptográfico (código muerto)

**CWE-338 · beemailboxes · `UtilsOtp.java:22-36`**

```java
public static String generarNumeroPar8Digitos() {
    var numero = ThreadLocalRandom.current().nextInt(LIMIT1, LIMIT2);
    if (numero % TEMP_2 != ZERO) { numero++; }        // fuerza que sea par
    ...
}
```

Dos debilidades: `ThreadLocalRandom` no es criptográficamente seguro (su estado es predecible a partir de salidas observadas), y forzar la paridad **reduce el espacio de códigos a la mitad** (45 millones en lugar de 90). La clase no se referencia desde ningún punto del código —el OTP real lo emite Celmedia—, por lo que hoy es código muerto y se clasifica como Low.

Debe eliminarse. Si en algún momento se necesitara generar códigos internamente:

```java
// Código recomendado
private static final SecureRandom RANDOM = new SecureRandom();

public static String generateOtp() {
    return String.format("%08d", RANDOM.nextInt(100_000_000));   // sin restricción de paridad
}
```

### SEC-042 — Endpoints internos y hostnames de infraestructura en el repositorio

**CWE-200 · becreditrisk, beclaims, beemailboxes**

Valores versionados que describen la infraestructura interna:

```text
becreditrisk/application-local.yml:15   jdbc:postgresql://db-nexhub.sva.cloud.scf.dev.corp:5432/CPED3AE1RDANEXHUBGENE001_DDB01
*/src/test/resources/config/*.properties  https://srvnuarintra.santander.dev.corp/pkm/v1/publicKey
*/src/test/resources/config/*.properties  https://srvnuarintra.santander.dev.corp/sts
beemailboxes/Constant.java:9            https://otpsantander.celmediamobile.pe/oauth/token
beclaims/application-local.yml:19       http://180.194.16.235/api_new
*/application-local.yml                 proxy.sig.umbrella.com:443
```

Además, los nombres de tablas DynamoDB (`cpei3ae1dynnexhubgene012`, `cped3ae1dynnexhubgene014`) y de la base de datos revelan la convención de nomenclatura corporativa, útil para un atacante que ya tenga acceso a la cuenta AWS. Externalizar por variable de entorno sin valor por defecto.

### SEC-043 — `automountServiceAccountToken: true` en despliegue productivo

> ### 🟡 Estado en v1.5 (re-verificado 2026-08-31) — **ATENUADO · de "todos" a 4 proyectos**
>
> Siete de los once servicios lo han puesto a `false` en los tres entornos. El estado actual:
>
> | En `false` (correcto) | En `true` (pendiente) |
> | --------------------- | --------------------- |
> | `becreditrisk`, `becustombeprogrm`, `bedatacomanagment`, `bedigitsignature`, `beidentbiometric` | `beclaims` (cert/pre/pro), `bedocmanagement` (cert/pre/pro), `beknowyocustomer` (cert/pre/pro), `beemailboxes` (**pre/pro**, corregido solo en cert) |
>
> `beproducoffering` y `bewatchscreening` no declaran la clave, por lo que heredan el valor por defecto del chart. Conviene fijarla explícitamente en lugar de confiar en el defecto.
>
> El caso de `beemailboxes` merece atención: se corrigió `cert` y se dejaron `pre` y `pro`. Es exactamente el patrón de remediación parcial que produce regresiones aparentes en la siguiente auditoría.


**CWE-250 · todos · `.gluon/cd/pro/values-pro.yaml`**

```yaml
serviceAccount:
  name: nexhub-tec-services-pro-sa
  automountServiceAccountToken: true
```

El token del ServiceAccount se monta en el pod. Es necesario para IRSA (que los servicios usan correctamente para asumir roles), pero el token de Kubernetes queda accesible en el sistema de ficheros del contenedor y podría emplearse contra la API de Kubernetes si el rol asociado tuviera permisos. Verificar que el `ClusterRole`/`Role` vinculado a `nexhub-tec-services-pro-sa` concede el mínimo imprescindible, y desactivar el montaje en los servicios que no interactúen con la API de Kubernetes (IRSA usa la proyección del token de OIDC, configurable de forma independiente).

### SEC-044 — Política de cabeceras inadecuada para APIs JSON

**CWE-1021 · todos · `SecurityConfig`**

```java
.headers(headers -> headers.contentSecurityPolicy(
        csp -> csp.policyDirectives("default-src 'self'; script-src 'self'; object-src 'none';")));
```

La CSP configurada es propia de una aplicación web con HTML; para una API que devuelve JSON no aporta protección. Las cabeceras que sí son relevantes en este contexto no se declaran explícitamente:

```java
// Código recomendado
.headers(headers -> headers
        .contentTypeOptions(Customizer.withDefaults())            // X-Content-Type-Options: nosniff
        .httpStrictTransportSecurity(hsts -> hsts
                .includeSubDomains(true)
                .maxAgeInSeconds(31536000))
        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
        .cacheControl(Customizer.withDefaults())                  // evita cacheo de respuestas
        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'")));
```

Nota sobre CSRF: `csrf(AbstractHttpConfigurer::disable)` esta presente en los once servicios y **es correcto** en este contexto — son APIs sin estado, sin cookies de sesión (`spring.session.store-type: none`) y con autenticación por cabecera. No se reporta como vulnerabilidad. Del mismo modo, **no se identificó ninguna configuración CORS**, lo que también es adecuado para APIs consumidas desde backends y desde una app móvil.

### SEC-045 — `jwks.json` presente pero no utilizado

**Informativo · beclaims · `src/main/resources/jwks.json`**

El fichero contiene dos claves RSA públicas (`kty: RSA`, `use: sig`, `alg: RS256`) con `kid` en formato base64, característico de Amazon Cognito. **Solo contiene material público**, por lo que no constituye una exposición de secretos. Está declarado explícitamente en los recursos empaquetados del `pom.xml` (`<include>**/jwks.json</include>`), pero ninguna clase lo referencia.

Es un vestigio de una implementación de validación de JWT que se dejó a medias — coherente con SEC-001. Al implementar la validación (SEC-001), **no debe usarse este fichero**: un JWKS estático provoca una caída del servicio en la primera rotación de claves de Cognito. Debe resolverse dinámicamente vía `issuer-uri`, y el fichero eliminarse.

### SEC-046 — Superficie declarada muy superior a la implementada

> ### 🟡 Estado en v1.5 (re-verificado 2026-08-31) — **ATENUADO**
>
> Los contratos se han recortado a lo implementado. La brecha pasa de **67 declaradas / ~26 implementadas** a **43 / 38**:
>
> | Proyecto | Declaradas v1.4 | Declaradas v1.5 | Implementadas v1.5 |
> | -------- | --------------: | --------------: | -----------------: |
> | `beknowyocustomer` | 20 | **3** | 2 |
> | `bedatacomanagment` | 8 | **1** | 1 |
> | `bedocmanagement` | 10 | 10 | 7 |
> | `beidentbiometric` | 13 | 13 | 13 |
> | Resto (7 proyectos) | 16 | 16 | 15 |
> | **Total** | **67** | **43** | **38** |
>
> Es la corrección más limpia del ciclo: reduce la superficie declarada, elimina la mayor parte del inventario fantasma que un pentester usaría como mapa (API9) y deja los contratos alineados con la realidad. Queda en Info por las cinco operaciones residuales, que se detallan en SEC-052.


**Informativo · todos · contratos OpenAPI**

| Proyecto | Operaciones declaradas | Implementadas | No implementadas |
| -------- | ---------------------: | ------------: | ---------------: |
| beknowyocustomer | 20 | 2 | 18 |
| bedocmanagement | 10 | 7 | 3 |
| bedatacomanagment | 8 | 3 | 5 |
| beidentbiometric | 13 | 13 | 0 |
| **Total** | **67** | **~26** | **~41** |

Con el patrón `delegatePattern` del generador, las operaciones sin implementación devuelven `501 Not Implemented` desde el método por defecto de la interfaz. No es una vulnerabilidad, pero: publica en el contrato una superficie que no existe, dificulta razonar sobre qué está realmente expuesto, y el propio contrato revela modelos de datos completos de funcionalidad futura.

Recomendación: mantener los contratos alineados con lo implementado, y publicar en el API Gateway únicamente las rutas con implementación real.

---

### SEC-052 — Endpoints declarados que responden 501 Not Implemented

> ### 🟡 Estado en v1.5 (re-verificado 2026-08-31) — **ATENUADO**
>
> De unas 26 operaciones declaradas sin implementar se baja a **cinco**, ninguna en `bedatacomanagment` (que pasó a 1 de 1):
>
> | Proyecto | Operación | Mecanismo |
> | -------- | --------- | --------- |
> | `bedocmanagement` | `PUT /documents/{document_id}` | Sin método en el delegate → default del generador |
> | `bedocmanagement` | `POST /documents/{document_id}/consolidate` | Sin método en el delegate → default del generador |
> | `bedocmanagement` | `POST /update_document` | Sin método en el delegate → default del generador |
> | `beknowyocustomer` | `GET /create` (`getKycInformation`) | `return CreateApiDelegate.super.getKycInformation(...)` — llamada explícita al default |
> | `beemailboxes` | `GET /health` | Sin método en el delegate → default del generador |
>
> El caso de `beknowyocustomer` es el que conviene mirar: el método **existe** en `HelloApiDelegateImpl:32-35` y delega en el `super` del generador. Una revisión que se limite a comprobar que el método está declarado lo dará por implementado; solo leyendo el cuerpo se ve que devuelve 501.


**CWE-1059 · beknowyocustomer, bedatacomanagment · contratos + delegates**

Con el patrón `delegatePattern` del generador OpenAPI, las operaciones sin implementación heredan el método por defecto de la interfaz, que devuelve `501 Not Implemented`:

```java
// beknowyocustomer/HelloApiDelegateImpl.java:33-35
@Override
public ResponseEntity<WrapperGetKnowYourCustomerResolution> getKycInformation(
        String partyId, String expand, String kycResolutionId) {
    return CreateApiDelegate.super.getKycInformation(partyId, expand, kycResolutionId);
}
```

`beknowyocustomer` declara 20 operaciones e implementa 2; `bedatacomanagment` implementa 3 de 8.

No es una vulnerabilidad: un `501` no expone datos ni permite acción alguna. Pero un `501` **confirma que el endpoint existe en el contrato**, lo que un revisor externo reporta como gestión deficiente del inventario de APIs (OWASP API9:2023). Y una superficie declarada que triplica la implementada dificulta razonar sobre qué está realmente expuesto.

Recomendación: alinear los contratos con lo implementado, o publicar en el API Gateway únicamente las rutas con implementación real, de modo que las demás no sean alcanzables.

---

### SEC-057 — El proyecto del Lambda Authorizer existe pero está vacío

> ### ⏸️ APLAZADO en v1.7 (2026-09-03) — fuera del alcance de este Ethical Hacking
>
> El proyecto `cpe-nxhbsc-lmauthorizer` completo queda fuera del EH. **Sigue siendo relevante para la calibración de SEC-001**: el control compensatorio del que depende toda la lectura del perímetro no está escrito en este repositorio. Si el gateway se apoya en otro artefacto, conviene confirmarlo con Arquitectura antes de la prueba.
>
> **El hallazgo sigue siendo válido y sigue abierto.** No se ha corregido nada: el código permanece desplegado y el defecto es explotable por quien tenga acceso a ese componente. Lo único que cambia es que **no se mide contra este ejercicio** y no cuenta en los 47 hallazgos de alcance — sí en los 56 de deuda técnica. Se conserva íntegro, con su evidencia y su remediación, para que al volver a alcance recupere su historial en lugar de reaparecer como hallazgo nuevo.

**Severidad:** Info · **Confianza:** CONFIRMADO · **Prioridad:** P1 *(por su relación con SEC-001)*
**CWE:** —
**Proyecto/API:** cpe-nxhbsc-lmauthorizer
**Nuevo en v1.5.**

#### Ubicación

```text
cpe-nxhbsc-lmauthorizer/          17 ficheros, ninguno con lógica de negocio
├── src/helloworld.js             función helloWorld() con un console.log
├── test/test.js
├── package.json                  "name": "my-component", sin scripts, sin dependencias
├── deployment.yml                AWS_ACCOUNT_ID: 111222333444 · S3BUCKET_NAME: "myBucket"
│                                 LAMBDA_NAME: "myLambdaName" · cabecera "SAMPLE VALUES - REPLACE"
└── readme.md                     documentación de la plantilla Gluon, sin adaptar
```

#### Por qué se documenta

No es una vulnerabilidad: es una plantilla Gluon recién generada, igual que `beemailsend`. Se registra porque **su ausencia de contenido es evidencia directa sobre la calibración de SEC-001**.

Toda la argumentación de §1.2 —y la rebaja de severidad que el diagrama de arquitectura permitió aplicar a varios hallazgos— descansa en que existe un autorizador en el API Gateway que valida el token de Cognito antes de que la petición alcance el pod. La frontera T4 de la tabla de confianza dice literalmente «Nadie autentica, nadie autoriza» del gateway hacia dentro, y se acepta porque el gateway lo hace fuera.

El repositorio contiene ahora un proyecto llamado `lmauthorizer` que, por nombre y por tipo (Lambda Node.js), es ese componente. Y está vacío. Caben dos explicaciones y conviene saber cuál es antes del Ethical Hacking:

* **El autorizador del gateway es nativo de Cognito** (un *Cognito User Pool Authorizer*), y este repositorio se creó para un autorizador Lambda personalizado que aún no se ha necesitado. En ese caso la calibración de SEC-001 se mantiene tal cual.
* **El diseño prevé un autorizador Lambda propio** —lo habitual cuando hay que validar *scopes*, resolver el `sub` a un identificador de cliente o consultar una lista de revocación— y **todavía no está escrito**. En ese caso, el control sobre el que se apoya la evaluación de todo este informe no existe todavía, y la calibración del §1.2 describe el destino, no el estado actual.

#### Acción recomendada

Confirmar con Arquitectura cuál de las dos es. Si es la segunda, la severidad efectiva de SEC-001 vuelve a Critical sin atenuación posible y su corrección deja de ser defensa en profundidad para pasar a ser el único control.

Con independencia de la respuesta: si el proyecto se va a implementar, `deployment.yml` debe dejar de contener `111222333444`, `myBucket` y `myLambdaName` antes del primer despliegue; y si no se va a implementar, conviene archivarlo para que no se interprete como un control existente.

---

## 8. Cadenas de ataque

Los hallazgos individuales adquieren su gravedad real al encadenarse. Se documentan las cuatro cadenas con evidencia confirmada en el código.

### CH-1 — Extracción masiva de datos de clientes con un token legítimo

```text
Usuario legítimo de la app móvil
   ↓ autenticación correcta contra Amazon Cognito              [el perímetro lo permite]
   ↓ Akamai → Imperva → AWS WAF → API Gateway                  [todos lo aceptan: el token es válido]
SEC-001  el backend descarta el JWT → no conoce al llamante
   +
SEC-002  customer_id / documentNumber / party_id se usan sin comprobar propiedad
   +
SEC-019  cuotas del gateway limitan el ritmo, no el alcance
   =
Enumeración de clientes con posición de tarjetas (beproducoffering),
perfil crediticio con marcas PEP/PLAFT (becreditrisk),
consentimientos de datos (bedatacomanagment) y score KYC (beknowyocustomer)
   +
SEC-001  sin identidad en los registros → sin atribución forense
```

**Severidad de la cadena: Critical.** Es la única que atraviesa el perímetro completo sin necesitar ninguna condición adicional.

### CH-2 — Descarga arbitraria de documentos por vía lateral

```text
Pod comprometido en la subred privada (o cualquier workload con ruta al NLB)
   ↓                                                          [no pasa por WAF/Cognito/APIGW]
SEC-001  ningún servicio autentica el tráfico este-oeste
   +
SEC-021  /download_document_intern acepta cabeceras estáticas (x-santander-client-id: 123),
         valores publicados en el repositorio, y no las valida
   +
SEC-014  /documents/{id}/versions devuelve los nombres de archivo de TODOS los documentos
   =
Enumeración del repositorio documental + descarga del binario de cualquier documento
   +
SEC-011  el contenido queda además volcado en base64 en el log
```

**Severidad de la cadena: Critical.** Requiere un punto de apoyo dentro del VPC, pero a partir de ahí no encuentra ningún control.

### CH-3 — Sustitución de un documento contractual

```text
SEC-014  obtener el nombre de archivo del documento objetivo
   +
SEC-002  conocer o inferir el ownerId del titular
   +
SEC-015  POST /upload_document con el mismo ownerId + name
         → la clave S3 se reconstruye idéntica → putObject sobrescribe
   =
El contrato original en S3 queda reemplazado por contenido del atacante
   +
SEC-015  con mimeType: text/html, el documento sustituto se sirve como HTML ejecutable
         a través de la URL prefirmada de descarga
```

**Severidad de la cadena: High.** El control que la rompería —versionado de objetos en el bucket— no es verificable desde el código.

### CH-4 — Autorización de una operación con un OTP ajeno

> **Actualización v1.6.** La cadena se ha simplificado: ya no hace falta un OTP ajeno. Como `validCode` descarta el veredicto del proveedor y responde `PROCESSED` ante cualquier código presente en la tabla (SEC-005), el eslabón de obtención del código pierde relevancia. El resto del flujo se mantiene tal cual.

```text
SEC-001  POST /{emailbox_id}/send_email accesible sin restricción de sujeto
   ↓ el atacante solicita un OTP para su propia dirección de correo
   ↓ lo recibe legítimamente
SEC-005  validCode() busca el OTP como clave primaria, sin comprobar a quién pertenece
   +
SEC-005  la condición de éxito es `status != null` — cualquier respuesta del proveedor vale
   +
SEC-019  sin límite de intentos ni de generación
   =
El OTP del atacante autoriza una operación asociada a otra persona
```

Vía alternativa, sin necesidad de generar nada:

```text
SEC-005  log.info("OTP generado: {}", otp)  →  OTP en claro en el agregador de logs
   +
SEC-022  POST /actuator/loggers sin autenticación (si la exposición se amplía)
   =
Lectura en tiempo real de los OTP de todos los usuarios
```

**Severidad de la cadena: Critical.**

### CH-5 — Volcado del repositorio documental con token válido *(reescrita en v1.6)*

```text
Usuario legítimo con token de Cognito válido
   ↓                                                    [el perímetro lo acepta: el token es correcto]
SEC-058  POST /search_documents
         { "discriminator":"OR", "searchProperties":[
             {"keyId":"NAME","keyOperator":"CONTAINS","keyValue":""} ] }
         → contains(attr,"") es cierto para toda cadena → Scan de tabla completa sin Limit
         → UNA petición devuelve todos los documentos del sistema
   +
SEC-048  el campo `name` de cada resultado es el `ownerId`, es decir el DNI del titular
         → relación documento → persona, ya resuelta en la misma respuesta
   +
SEC-002  ninguna comprobación de titularidad en ningún punto del flujo
   =
Inventario documental íntegro + DNI de cada propietario, en una llamada
   ↓
SEC-002  POST /download_document  { "document": { "documentId": "<id del volcado>" } }
         → URL prefirmada de S3, válida 10 minutos, sin verificar titularidad
   =
Descarga del contenido de cualquier documento contractual del sistema
```

**Severidad de la cadena: Critical.** Es enteramente ejecutable desde fuera con un token válido, sin ninguna condición adicional: ni acceso a la red interna, ni compromiso previo, ni bypass del gateway. Los cuatro hallazgos están en el mismo servicio.

> **Qué ha cambiado respecto a v1.5.** La cadena anterior partía de SEC-014 (`/versions` devolvía la tabla entera) y remataba en SEC-049 (borrado ajeno). **Ambos extremos se han cerrado en esta entrega** — `/versions` consulta por clave y el borrado ya no es alcanzable — y sin embargo **la cadena no solo sigue viva: es más corta y más eficiente**. Donde antes hacían falta tres peticiones y un oráculo de enumeración, ahora basta una.
>
> Es el argumento más claro a favor de arreglar SEC-002 y no sus síntomas: mientras la autorización de objeto no exista, cerrar endpoints uno a uno solo desplaza la cadena al siguiente. La única pérdida real para el atacante es la capacidad de **destruir** documentación; la de **leerla toda** ha mejorado.

---

### CH-6 — Salto de silo de datos por identidad IAM compartida *(nueva en v1.5)*

```text
Compromiso de UN pod cualquiera de los dos afectados
   ↓                                              [basta un RCE, una dependencia vulnerable o SEC-016 + SEC-017]
SEC-043  automountServiceAccountToken: true  (en beclaims, bedocmanagement,
         beknowyocustomer y beemailboxes pre/pro)
         → el token del ServiceAccount está montado en el contenedor
   +
SEC-054  bedigitsignature asume ${AWS_IRSA_BEDOCMANAGEMENT}
         → credenciales STS con la política del gestor documental
   =
Acceso directo al bucket S3 documental y a su tabla de metadatos,
SIN pasar por bedocmanagement
   ↓
El control que SEC-021 propone añadir en la frontera bedigitsignature → bedocmanagement
queda sin efecto: el atacante ya no necesita esa llamada
```

La variante con `becustombeprogrm` es equivalente y llega a la tabla de OTP:

```text
becustombeprogrm asume ${AWS_IRSA_BEEMAILBOXES}
   → credenciales con la política de beemailboxes
   → lectura directa de la tabla de OTP en DynamoDB
   + SEC-005 (validCode acepta cualquier OTP presente en la tabla, sin vínculo a usuario)
   = autorización de una operación ajena con un OTP leído, no adivinado
```

**Severidad de la cadena: High.** Requiere un compromiso previo, así que no es explotable desde fuera; pero es exactamente el escenario de "contenedor comprometido" que §7 de `EH_PREVIEW.md` recomienda incluir en el alcance del Ethical Hacking. Su valor está en que **degrada dos controles que el informe daba por útiles**: la segmentación este-oeste que SEC-021 propone reforzar, y el aislamiento por identidad que la arquitectura IRSA existe para proporcionar.

---

## 9. Matriz consolidada

| ID | Sev. | Conf. | Proyecto | Archivo | Línea | Hallazgo | Riesgo | Sugerencia de corrección | Prio. |
| -- | ---- | ----- | -------- | ------- | ----: | -------- | ------ | ------------------------ | ----- |
| SEC-001 | Critical | CONF | Todos | `SecurityConfig.java` / `config/application.yml` | 31-42 / 22-25 | `anyRequest().permitAll()` + `security.enabled: false` | Sin autenticación en T4/T5 | `oauth2ResourceServer` con `issuer-uri` de Cognito; `anyRequest().authenticated()`; mTLS o token de servicio en este-oeste | P0 |
| SEC-002 | Critical | CONF | 8 proyectos | `HelloApiDelegateImpl.java`, `CreditRiskManagementInputPort.java`, `DataConsentManagementAdapter.java` | 64-72, 46-77, 37-93 | Identificadores de objeto sin control de propiedad | BOLA: datos de cualquier cliente | `AuthorizationService.assertCanAccessCustomer(jwt, id)` antes de cada acceso; `scope` explícito para acceso masivo | P0 |
| SEC-003 | Critical | CONF | 6 proyectos | `application-local/cert/pre.yml`, `Constant.java` | varias / 28 | 18 secretos versionados | Compromiso de proveedores y BD | Rotar los 18; eliminar defaults; migrar a Secrets Manager; `gitleaks` en CI | P0 |
| SEC-004 | Critical | CONF | 7 proyectos | `WebClientConfig.java`, `RestTemplateConfig.java` | 52-54, 31-42 | `InsecureTrustManagerFactory` / `TrustStrategy → true` / `NoopHostnameVerifier` | MITM en salida a terceros | Truststore con CA de Netskope; eliminar `handlerConfigurator` vacío | P0 |
| SEC-005 | Critical | CONF | beemailboxes | `OTPServiceAdapter.java` | 60-80, 98-114 | OTP sin vínculo a usuario, sin límite, en path y en log | Bypass de 2FA | Clave = transactionId; validar sujeto; contador de intentos; TTL; OTP fuera del path y del log | P0 |
| SEC-006 | Critical | CONF | bedigitsignature | `Constant.java` | 64-65 | Callback a `webhook.site`; `replace("JWT")` no sustituye | Fuga a tercero; callback sin autenticación | `callbackUrl` por entorno; construir el header sin marcador; publicar endpoint propio con validación de JWT | P0 |
| SEC-007 | Critical | CONF | 4 proyectos | `TokenService.java`, `AesEncryptionService.java`, `DocumentProcessService.java` | 50, 87, 33, 106 | Password, access token, clave AES y JWT en logs | Credenciales en el agregador | `@ToString.Exclude`; registrar metadatos, no objetos; masking en el appender | P0 |
| SEC-008 | Critical | CONF | becreditrisk | `data.sql` | 1-54 | DNI reales con marcas PLAFT/PEP | Brecha de datos sensibles | Eliminar y purgar historial; datos sintéticos en `src/test`; excluir del empaquetado | P0 |
| SEC-009 | High | CONF | beclaims | `application-local.yml` | 19 | `http://` hacia Contáctanos (GSNET) | Credenciales en claro en red interna | Migrar a HTTPS; validar esquema en el arranque; rotar credenciales | P1 |
| SEC-010 | Critical | CONF | beclaims | `ClaimsAdapter.java` | 63, 69-74, 90, 119, 154 | `onErrorResume` → mock con `complaintBookId` fijo | Reclamos perdidos con confirmación falsa | Eliminar mocks; propagar 503; store-and-forward con reintento asíncrono | P0 |
| SEC-011 | High | CONF | bedigitsignature | `DocumentClient.java` | 80 | Documento base64 completo en log | Exfiltración vía logs | `log.debug` con `documentId` y tamaño | P1 |
| SEC-012 | High | CONF | beidentbiometric | `FacephiAdapter.java` | 84, 124 | `token1`, `bestImageToken`, `tokenOcr` en log | Biometría en logs | `@ToString.Exclude` en los DTO; registrar solo `trackingId` | P1 |
| SEC-013 | High | CONF | 6 proyectos | `WebClientConfig.java` | 65, 84, 33, 89, 64, 64 | `wiretap(true)` | Volcado de credenciales al elevar el log | Condicionar por propiedad; `AdvancedByteBufFormat.SIMPLE`; fijar la categoría a `WARN` | P1 |
| SEC-014 | High | CONF | bedocmanagement | `DocumentManagementAdapter.java` | 188 | `getDocumentVersion` ignora el id y hace `findAll()` | Enumeración del repositorio + DoS | `queryByPartitionKey`; eliminar `findAll()` del repositorio base | P1 |
| SEC-015 | High | ALTA | bedocmanagement | `DocumentManagementAdapter.java` | 120-129, 146-168 | Clave S3 y `Content-Type` desde el request | Sobrescritura de documentos; XSS almacenado | Clave derivada de hash + UUID; MIME detectado con Tika; `contentDisposition: attachment`; versionado del bucket | P1 |
| SEC-016 | High | CONF | 3 proyectos | `WebClientConfig.java`, `RestTemplateConfig.java` | 20-34, 28-63, 37-50 | Clientes HTTP sin timeout | Agotamiento del pool de hilos | `CONNECT_TIMEOUT_MILLIS` + `responseTimeout` + `Read/WriteTimeoutHandler`; `RequestConfig` en Apache | P1 |
| SEC-017 | High | CONF | becustombeprogrm | `SKYServiceAdapter.java` | 94 | Retry sobre `POST /v1/user` | Altas duplicadas | `Idempotency-Key`; o restringir el retry a `ConnectException` | P1 |
| SEC-018 | High | CONF | becustombeprogrm, bedigitsignature | `SKYServiceAdapter.java`, `Util.java` | 104-131, 99-111 | `rawBody` del proveedor al consumidor | Divulgación de infraestructura de terceros | Detalle al log con `correlationId`; al consumidor, código `TL*` + referencia | P1 |
| SEC-019 | High | ALTA | Todos | — | — | Sin rate limiting; amplificación 1→2N | Agotamiento de recursos y de cuota | `maxItems` en contratos; `RateLimiter` por sujeto; usage plans en el gateway; circuit breakers | P1 |
| SEC-020 | High | CONF | 4 proyectos | contratos + `DocumentManagementAdapter.java` | 115 | base64 sin `maxLength`; arrays sin `maxItems` | OOM y reinicio de pods | `maxLength`/`maxItems`/`pattern` en el contrato; validación de tamaño antes de decodificar | P1 |
| SEC-021 | High | CONF | bedocmanagement, bedigitsignature | `openapi.yaml`, `WebClientConfig.java` | 272, 38-50 | Endpoint interno en contrato público; cabeceras estáticas no validadas | Descarga arbitraria por vía lateral | Contrato interno con `scope` propio; token de servicio o mTLS; `NetworkPolicy` | P1 |
| SEC-022 | High | CONF | Todos | `application.yml`, `SecurityConfig.java` | — | `/actuator/**` `permitAll` + `show-details: ALWAYS` | Reconocimiento; `loggers` habilita SEC-013 | `exposure.include` explícito; `when-authorized`; `management.server.port` separado | P1 |
| SEC-023 | High | CONF | becustombeprogrm, bedigitsignature | `SkyTokenService.java`, `JwtUtil.java` | 36-53, 30-47 | JWT sin `iss`/`aud`/`jti`; AES key = JWT key; exp 20 s | Token reutilizable; radio de compromiso ampliado | Claims registrados completos; claves separadas y verificadas en el arranque; migrar a jjwt 0.12 | P1 |
| SEC-024 | Medium | CONF | becustombeprogrm | `AesEncryptionService.java` | 30-46 | AES/CBC sin autenticación; transformación configurable | Manipulación de texto cifrado; padding oracle | AES/GCM con transformación fija; o encrypt-then-MAC | P2 |
| SEC-025 | Low | CONF | Todos | `application.yml` | — | Swagger habilitado en todos los perfiles | Contrato completo por vía lateral | `springdoc.api-docs.enabled: false` en pro/pre/cert | P3 |
| SEC-026 | Medium | CONF | becreditrisk | `CreditRiskDelegateImpl.java` | 36-37 | `society`/`channel` sin validar hacia Modellica | Influencia en la decisión de riesgo | Lista blanca; preferible derivar del token | P2 |
| SEC-027 | Medium | REQ | Todos | `application.yml` | — | `forward-headers-strategy: framework` | IP de origen falsificable en logs | Verificar normalización en Imperva/APIGW; `ForwardedHeaderFilter` con proxies de confianza | P2 |
| SEC-028 | Medium | CONF | 5 proyectos | varios | ver §6 | `.get()`, `get(0)`, `Integer.valueOf` sin control | 500 con posible detalle interno | `orElseThrow` con código `TL*`; handler `Exception.class` con `correlationId` | P2 |
| SEC-029 | Medium | CONF | beproducoffering | `application-pro.yml` | — | `ddl-auto: update`, `sql.init.mode: always` | Alteración de esquema en producción | `validate` + `never`; migraciones con Liquibase/Flyway | P2 |
| SEC-030 | Medium | CONF | bedatacomanagment | `DataConsentManagementAdapter.java` | 83 | `putIfAbsent` en una actualización | La revocación de consentimiento nunca se aplica | `updateItem` con `ignoreNulls` | P2 |
| SEC-031 | Medium | CONF | bedigitsignature | `Entity.java` | 57-67 | JWT como partition key, atributo `documentNumber` | Token en índices y backups | PK = `loteId`, SK = `documentId`; almacenar solo `jti`; TTL | P2 |
| SEC-032 | Medium | CONF | bedigitsignature | `DocumentClient.java` | 37-46 | Rama `CONTRATO_CLIENTE` → PDF del classpath | Firma de un documento de pruebas | Eliminar la rama; stub en tests; retirar `test.pdf` | P2 |
| SEC-033 | Medium | CONF | beclaims | `TokenService.java` | 38-43 | Token cacheado sin expiración | Fallo permanente enmascarado por SEC-010 | `CachedToken` con expiración, como en becreditrisk | P2 |
| SEC-034 | Medium | CONF | Todos | `pom.xml` | — | 3 versiones de parent; Netty 4.1.x + 4.2.x en bedatacomanagment | Incompatibilidad binaria; build fragil | Unificar parent en 1.6.0; BOM comun; una sola linea de Netty | P2 |
| SEC-035 | Medium | CONF | beemailboxes | `JsonTokenProvider.java`, `XmlTokenProvider.java` | 56, 116 | `assert` para control de flujo | NPE → 500 | `if (…) throw new BusinessException(...)` | P2 |
| SEC-036 | Medium | REQ | beemailboxes | `XmlApiClient.java` | 31, 124 | `XmlMapper` sin endurecer | XXE si cambia el backend | `XMLInputFactory` con DTD y entidades externas deshabilitadas | P2 |
| SEC-037 | Medium | CONF | 3 proyectos | varios | — | Sin `Idempotency-Key` ni `jti`/`nonce` | Duplicación y replay | Cabecera `Idempotency-Key` requerida; almacén con TTL | P2 |
| SEC-038 | Medium | REQ | 6 proyectos | varios | — | Datos externos en logs sin neutralizar | Log injection; PII en logs | Confirmar escape de GLUONLOG; sanear CR/LF; enmascarar documentos | P2 |
| SEC-039 | Medium | CONF | bedocmanagement | `BaseDynamoRepository.java` | 76-92 | `Scan` completo con `filterExpression` | Coste y DoS; BOLA | GSI por `ownerId` + `query` con `limit` y paginación | P2 |
| SEC-040 | Medium | ALTA | bewatchscreening | `GesintelAdapter.java` | 100-115 | `result` siempre `"Match Found"` | Falsos positivos AML sistemáticos | Derivar `result` del código de respuesta | P2 |
| SEC-041 | Low | CONF | beemailboxes | `UtilsOtp.java` | 22-36 | `ThreadLocalRandom` + paridad forzada (código muerto) | Predecibilidad si se usara | Eliminar; si se necesita, `SecureRandom` sin restricción de paridad | P3 |
| SEC-042 | Low | CONF | 3 proyectos | `application-local.yml`, test properties | — | Hostnames internos y nombres de tablas | Reconocimiento de infraestructura | Externalizar sin defaults | P3 |
| SEC-043 | Low | CONF | Todos | `values-pro.yaml` | — | `automountServiceAccountToken: true` | Token de K8s accesible en el pod | Revisar permisos del SA; desactivar donde no se use la API de K8s | P3 |
| SEC-044 | Low | CONF | Todos | `SecurityConfig.java` | 44-49 | CSP de app web en una API JSON | Cabeceras de seguridad no alineadas | `nosniff`, HSTS, `frameOptions: deny`, `cache-control` | P3 |
| SEC-045 | Info | CONF | beclaims | `jwks.json` | — | JWKS estático sin uso | Rotura ante rotación si se llegara a usar | Eliminar; resolver el JWKS vía `issuer-uri` | P3 |
| SEC-046 | Info | CONF | Todos | contratos OpenAPI | — | 67 declaradas / ~26 implementadas | Superficie documentada enganosa | Alinear contratos; publicar en el gateway solo lo implementado | P3 |
| SEC-047 | High | CONF | bedocmanagement | `DocumentManagementAdapter.java` | 61-71, 178-185, 200-215 | Tres respuestas distintas ante recurso inexistente | Oráculo de existencia; habilita SEC-002/048/049 | Unificar en 404 tras comprobar titularidad | P1 |
| SEC-048 | High | CONF | bedocmanagement | `DocumentMapper.java` | 111-118 | El campo `name` devuelve el DNI del titular | Exposición de datos personales | `setName(entity.getFileName())`; titular solo al titular y enmascarado | P1 |
| SEC-049 | High | CONF | bedocmanagement | `DocumentManagementAdapter.java` | 200-215 | Borrado sin verificar titularidad ni existencia | Destrucción de documentación contractual | Comprobar titularidad; auditar; versionado de bucket; borrado lógico | P1 |
| SEC-050 | Medium | CONF | becustombeprogrm | `QurableServiceAdapter.java` | 80-92, 169-178 | El path variable elige el verbo HTTP saliente | Semántica destructiva gobernada por el consumidor | La acción va en el cuerpo como enum; validar y devolver 400 | P2 |
| SEC-051 | Medium | CONF | bedocmanagement | `FileEntity.java`, `DocumentMapper.java` | 18-36, 71-90 | `customerId` guarda el id del documento, no el cliente | Induce a implementar mal el control de SEC-002 | Renombrar campos manteniendo `@DynamoDbAttribute` | P2 |
| SEC-052 | Low | CONF | beknowyocustomer, bedatacomanagment | contratos + delegates | — | Endpoints declarados que responden 501 | Inventario de APIs deficiente (API9) | Alinear contratos; publicar solo lo implementado | P3 |
| SEC-053 | High | CONF | beemailboxes | `EmailboxIdInputPort.java`, `RateLimiterConfig.java` | 39-70 / 12-22 | El rate limiter cubre `sendMailing` y no `validCode`; registro sin cota keyed por email del cliente | Fuerza bruta del 2FA + agotamiento de memoria | Limitar también la validación, por operación; acotar el registro con TTL y tamaño máximo; contador de intentos en DynamoDB | P1 |
| SEC-054 | High | CONF | becustombeprogrm, bedigitsignature | `application-*.yml` | 34 / 63 | `role-arn: ${AWS_IRSA_BEEMAILBOXES}` y `${AWS_IRSA_BEDOCMANAGEMENT}` en servicios que no son esos | Privilegio excesivo y pérdida de atribución en CloudTrail | Usar `AWS_IRSA_<propio componente>`; crear roles con política mínima; comprobación en CI | P1 |
| SEC-055 | High | CONF | becustombeprogrm | `.gluon/cd/pro/values-pro.yaml` | 37-42 | `SEC_QURABLE_JWT_TOKEN` desde `dev-publickey-nexhub` en el chart de producción | Credencial productiva compartida con desarrollo | Cambiar a `pro-publickey-nexhub`, dar de alta la clave con valor nuevo y rotar el de desarrollo | P1 |
| SEC-056 | Medium | CONF | 4 proyectos | `application-pro.yml`, `application-pre.yml`, `application.yml` | varias | `${VAR:xx}`, `${VAR:test}`, `${SEC_SKY_JWT_SECRET:12}` en perfiles no locales | Arranque silencioso con configuración falsa en vez de fallo rápido | Eliminar el defecto en `pre`/`pro` y en ficheros base; `@ConfigurationProperties` con `@Validated` + `@NotBlank` | P2 |
| SEC-057 | Info | CONF | lmauthorizer | `src/helloworld.js`, `deployment.yml` | 1-6 | Plantilla Gluon sin implementar en el proyecto del Lambda Authorizer | Condiciona la calibración de SEC-001 | Confirmar con Arquitectura si el autorizador del gateway es nativo de Cognito o este componente; archivar o implementar | P1 |

---

## 10. Integration Security Matrix

| API | Consume | Autenticación | TLS | Validación cert. | Token | Timeout | Retry | Riesgo |
| --- | ------- | ------------- | --- | ---------------- | ----- | ------- | ----- | ------ |
| beclaims | Contáctanos (GSNET) | Usuario/contraseña en JSON | **HTTP** | n/a | Bearer propietario, **sin expiración** (SEC-033) | 5000 ms | No | **CRÍTICO** |
| becreditrisk | Modellica / DataView360 | OAuth2 `client_credentials` | HTTPS | **Desactivada** | Bearer con expiración correcta; **loggeado** (SEC-007) | 5000 ms | No | **CRÍTICO** |
| becustombeprogrm | SKY Airline | JWT HS256 propio + `Ocp-Apim-Subscription-Key` | HTTPS | **Desactivada** | Sin `iss`/`aud`/`jti`; clave = clave AES (SEC-023) | **Ninguno** | **3 intentos sobre POST** | **CRÍTICO** |
| becustombeprogrm | Qurable | Token estático de configuración | HTTPS | **Desactivada** | Token fijo, sin rotación | **Ninguno** | 3 intentos | **ALTO** |
| bedigitsignature | bedocmanagement (interno) | **Cabeceras estáticas** (`x-santander-client-id: 123`) | Según `DOCUMENT_URL` | n/a (sin connector) | Ninguno | **Ninguno** | No | **CRÍTICO** |
| bedigitsignature | FacePhi / Zytrust | `x-api-key` | HTTPS + proxy | **Desactivada** | API key estática | 50 000 ms | No | **CRÍTICO** |
| bedocmanagement | AWS S3 + DynamoDB | IRSA + `AssumeRole` | HTTPS (SDK) | Por defecto (correcta) | STS temporal, autorrenovado | SDK | SDK | BAJO |
| beemailboxes | Celmedia OTP | OAuth2 `client_credentials` (Basic) | HTTPS | **Desactivada + hostname** | Bearer con expiración | **Ninguno** | No | **CRÍTICO** |
| beemailboxes | Acoustic / Celmedia correo | OAuth2 `refresh_token` **hardcodeado** | HTTP en `url-send-mail` por defecto | **Desactivada + hostname** | Bearer con expiración | **Ninguno** | No | **CRÍTICO** |
| beidentbiometric | FacePhi | `x-api-key` (dos claves distintas) | HTTPS + proxy | **Desactivada** | API key estática | 10 000 ms | No | **ALTO** |
| beknowyocustomer | DynamoDB | IRSA + `AssumeRole` | HTTPS (SDK) | Por defecto (correcta) | STS temporal | SDK | SDK | BAJO |
| beproducoffering | RDS Postgres | Usuario/contraseña | Según `SEC_RDS_DB_URL` | No verificable | n/a | Hikari 20 000 ms | n/a | MEDIO |
| bewatchscreening | Gesintel / AMLUpdate | Usuario/contraseña → token | HTTPS | **Desactivada** | Token con expiración correcta | **500 ms** (demasiado bajo) | No | **ALTO** |

**Lectura de la matriz:**

* **Ninguna integración usa mTLS.** No se encontró un solo `keyManager`, `KeyStore` de cliente ni certificado de cliente en el código. Toda la autenticación saliente es por API key, contraseña o bearer.
* **Siete de trece integraciones tienen la validación de certificado desactivada** (SEC-004).
* **Cuatro no tienen ningún timeout** (SEC-016), y una lo tiene demasiado bajo.
* **Las únicas integraciones con postura correcta son las de AWS** (IRSA + STS AssumeRole + SDK con validación por defecto).

---

## 11. Security Hotspots

| Proyecto | Archivo / Componente | Riesgo | Motivo |
| -------- | -------------------- | ------ | ------ |
| Todos | `infrastructure/config/SecurityConfig.java` | **CRÍTICO** | `anyRequest().permitAll()`; punto único donde se restablecería la autenticación de las 11 APIs |
| Todos | `src/main/resources/config/application.yml` | **CRÍTICO** | `santander.security.enabled: false` + `white-list: /**` + actuator con detalle |
| beemailboxes | `adapters/output/OTPServiceAdapter.java` | **CRÍTICO** | Genera, persiste, registra y valida el OTP; concentra el bypass de 2FA completo |
| beemailboxes | `infrastructure/constants/Constant.java` | **CRÍTICO** | Refresh token OAuth2 hardcodeado |
| bedigitsignature | `infrastructure/utils/Constant.java` | **CRÍTICO** | Callback a `webhook.site` y cabecera con token literal |
| bedigitsignature | `adapters/output/DocumentProcessService.java` | **CRÍTICO** | Orquesta firma, JWT, callback y persistencia; concentra SEC-006, SEC-007, SEC-018, SEC-028, SEC-031 |
| bedocmanagement | `adapters/output/DocumentManagementAdapter.java` | **CRÍTICO** | Construcción de claves S3, MIME del cliente, `findAll()`, sin autorización, enumeración diferencial y borrado sin control (SEC-014, 015, 039, 047, 049) |
| bedocmanagement | `adapters/output/DocumentMapper.java` | **ALTO** | Publica el DNI del titular y cruza los campos del modelo (SEC-048, SEC-051) |
| beclaims | `adapters/output/client/ClaimsAdapter.java` | **CRÍTICO** | Cuatro fail-open con datos fabricados sobre un proceso regulado |
| 7 proyectos | `infrastructure/config/WebClientConfig.java` / `RestTemplateConfig.java` | **CRÍTICO** | Trust-all, `wiretap`, ausencia de timeouts — el mismo patrón replicado |
| becustombeprogrm | `infrastructure/util/AesEncryptionService.java` | **ALTO** | Clave AES en logs, cifrado sin autenticación, supresión de la regla de análisis |
| becreditrisk / beclaims / bewatchscreening | `.../client/TokenService.java` | **ALTO** | Manejo de credenciales y tokens; tres implementaciones divergentes del mismo patrón |
| beidentbiometric | `adapters/output/client/rest/FacephiAdapter.java` | **ALTO** | Trece llamadas con datos biométricos; dos con volcado al log |
| becreditrisk | `src/main/resources/data.sql` | **ALTO** | Datos personales sensibles versionados |
| Todos | `.github/workflows/security.yml` | **MEDIO** | El *gate* de seguridad de CI no incluye detección de secretos ni SAST propio |

---

## 12. Dependency Security Review

**Metodología y limitación.** Esta sección se basa exclusivamente en las versiones declaradas en los `pom.xml`. **No se ejecutó ningún análisis de composición de software** (OWASP Dependency-Check, Snyk, Trivy) porque el entorno de revisión no dispone de acceso a la base de datos de vulnerabilidades. **No se afirma la existencia de ningún CVE**: hacerlo sin verificación sería inventar evidencia. Las observaciones son de gestión de versiones y de soporte.

**Valoración general: correcta.** Es el área mejor gestionada del conjunto. Las versiones fijadas son actuales y muestran un esfuerzo deliberado de mantenimiento (Spring Boot 3.5.14, Spring Security 6.5.11, Netty 4.1.136, Jackson 2.21.5, Tomcat 10.1.55, log4j 2.25.4, commons-lang3 3.18.0, httpclient5 5.6.4).

| Proyecto | Dependencia | Versión | Severidad | CVE | Riesgo | Recomendación |
| -------- | ----------- | ------- | --------- | --- | ------ | ------------- |
| becustombeprogrm, bedigitsignature, beemailboxes | `io.jsonwebtoken:jjwt-*` | 0.11.5 | Medium | **No verificado** | Línea 0.11.x sin mantenimiento activo; API usada (`setClaims`, `signWith(key, alg)`) deprecada en 0.12 | Migrar a **0.12.x** y actualizar la API (ver SEC-023) |
| beclaims, becreditrisk, bedatacomanagment, beidentbiometric, bewatchscreening | `jackson-databind` | 2.18.8 | Low | **No verificado** | Cinco proyectos por detrás de los otros cinco (2.21.5) | Unificar en la versión más reciente |
| beclaims, bedatacomanagment | `netty-handler`, `netty-resolver-dns` | 4.1.135.Final | Low | **No verificado** | Una versión por detrás del resto (4.1.136) | Unificar |
| bedatacomanagment | `netty-codec-http`, `netty-codec-http2`, `netty-transport-native-epoll` | 4.2.13.Final | Medium | n/a | **Mezcla de líneas 4.1.x y 4.2.x en el mismo proyecto** (`netty-handler` 4.1.135 + `netty-codec-http` 4.2.13); riesgo de incompatibilidad binaria | Fijar una única línea de Netty |
| becreditrisk, becustombeprogrm, bedatacomanagment, beidentbiometric | `software.amazon.awssdk:sts` | 2.40.13 | Low | **No verificado** | Desalineada con `apache-client` 2.42.33 del mismo proyecto | Usar el BOM `aws-sdk-bom` |
| Todos | `santander-spring-boot-starter-parent` | 1.5.1 / 1.5.2 / 1.6.0 | Medium | n/a | Tres versiones del parent corporativo entre servicios del mismo dominio | Unificar en 1.6.0 |
| beclaims | `tomcat-embed-core` | 10.1.55 (`<scope>compile</scope>`) | Low | n/a | El scope explícito `compile` sobre una dependencia gestionada por el starter puede duplicar la clase en el artefacto | Retirar el `<scope>` |

**Observación de proceso.** El patrón dominante en los `pom.xml` es la **sobrescritura manual de versiones transitivas** (Netty, Jackson, Spring, Tomcat fijados uno a uno). Es sintomático de remediación reactiva ante hallazgos de escaneo: funciona, pero es frágil y genera exactamente la deriva que muestra la tabla. La solución estructural es que el parent corporativo gestione esas versiones mediante `dependencyManagement`, y que los proyectos no las fijen.

**Recomendaciones:**

1. Ejecutar **OWASP Dependency-Check** o **Snyk** sobre los once proyectos para obtener el inventario real de CVE; esta revisión no puede sustituir esa comprobación.
2. Incorporar el análisis SCA como *gate* bloqueante en `.github/workflows/security.yml` (hoy solo invoca el workflow reutilizable de imagen).
3. Unificar el parent en 1.6.0 y eliminar los overrides manuales que ese parent ya cubra.
4. Resolver la mezcla de líneas de Netty en `bedatacomanagment` — es el único caso con riesgo técnico inmediato de la tabla.

---

## 13. Existing Security Controls

Controles correctamente implementados, que deben preservarse:

| Control | Ubicación | Valoración |
| ------- | --------- | ---------- |
| **Perímetro de red completo** | Akamai → Imperva → AWS WAF → Cognito → API Gateway → PrivateLink → NLB → subred privada | Sólido. Es lo que hoy sostiene la seguridad del conjunto |
| **Credenciales AWS por IRSA + STS AssumeRole** | `DynamoDBConfig`, `S3Config` (todos los proyectos) | Correcto. Sin claves estáticas, con renovación asíncrona y roles por servicio |
| **Secretos de producción vía Kubernetes Secrets** | `.gluon/cd/pro/values-pro.yaml` (`secretKeyRef`, `optional: false`) | Correcto. El mecanismo existe y funciona — el problema es que no se usa de forma exclusiva |
| **Contenedor sin privilegios** | `Dockerfile` (todos): `USER 20000:20000`, imagen base corporativa, build multi-etapa con capas de Spring Boot | Correcto |
| **Sanitización antes de persistir datos biométricos** | `BiometricInputPort.cleanData()` (`beidentbiometric`, líneas 394-415) | Correcto **en lo esencial**: trunca cadenas > 500 car., con lo que las plantillas faciales e imágenes no llegan a DynamoDB. **Ya existía en v1.5**, no es una mejora de este ciclo. Insuficiente para DNI y tokens cortos — ver SEC-059 |
| **DTO de FacePhi sin `toString()` generado** | 26 de los 28 DTO de `beidentbiometric` (solo `@Getter @Setter @Builder`) | Correcto, y es lo que impide que los 14 `log.warn(request)` vuelquen datos biométricos (SEC-012). **Frágil**: se pierde añadiendo `@Data` a cualquiera de ellos |
| **Mapeo de errores de proveedor a códigos corporativos** | `SKYServiceAdapter:61-93` (`becustombeprogrm`), `FacephiAdapter.handle4xxError/handle5xxError` (`beidentbiometric`) | Correcto. Registra el detalle del proveedor en el log interno y devuelve `TL*` al consumidor. **Es el patrón a replicar** en Qurable y `bedigitsignature` (SEC-018) |
| **Validación TLS y timeouts en `beemailboxes`** | `RestTemplateConfig:31-68`: `SSLContexts.createSystemDefault()`, `DefaultHostnameVerifier`, TLS 1.2/1.3, timeouts de 10 s | Correcto. **Es el patrón de referencia** para los 6 servicios con `InsecureTrustManagerFactory` (SEC-004) |
| **Validadores de entrada en carga y descarga** | `UploadDocumentValidator`, `DownloadDocumentValidator` (`bedocmanagement`) | Correcto en su alcance. **No son nuevos**: `UploadDocumentValidator` ya se citaba en SEC-020 en v1.5. **No cubren `search_documents`**, que es el endpoint que hoy más expone (SEC-058), ni imponen límite de tamaño al base64 |
| **Filtrado de reintentos por tipo de fallo** | `WebClientRetryPolicy:21-27` (`becustombeprogrm`) | Correcto. Excluye los 4xx del reintento; falta la clave de idempotencia (SEC-017) |
| **Construcción segura de expresiones DynamoDB** | `ExpressionBuilder` + `FileSearchMapper.mapField` (`bedocmanagement`) | Correcto. Marcadores `#n`/`:v` y campos validados contra enum: **sin inyección** |
| **Consultas JPA parametrizadas** | `CmaRepository.java:18` (`becreditrisk`) | Correcto. Único `@Query` del conjunto, con `:documentNumber` vinculado |
| **URLs prefirmadas con vida corta** | `DocumentManagementAdapter.generateDownloadUrl` — 10 minutos | Correcto |
| **Validación de campos obligatorios en KYC** | `OnboardingValidator` (`beknowyocustomer`) | Correcto y exhaustivo — es el estándar que deberían seguir los demás |
| **Validación de formato de identificador** | `CustomerIdValidator` (`beproducoffering`) | Correcto en su alcance (formato); insuficiente como autorización (SEC-002) |
| **Envelope de error corporativo** | `ControllerAdvice` + enums `Exceptions` con códigos `TL*` (7 proyectos) | Correcto. Códigos estables sin detalle interno — salvo las excepciones de SEC-018 |
| **Manejo de expiración de token** | `TokenService` de `becreditrisk` y `bewatchscreening` | Correcto. Es el patrón que `beclaims` debería adoptar (SEC-033) |
| **Timeouts completos en clientes HTTP** | `WebClientConfig` de `beclaims`, `becreditrisk`, `beidentbiometric`, `bewatchscreening` | Correcto. Connect + response + read + write |
| **Gestión de versiones de dependencias** | `pom.xml` (todos) | Buena. Versiones actuales, con esfuerzo evidente de mantenimiento |
| **Pipeline con etapas de calidad y seguridad** | `.github/workflows/` (quality, security, version-validation) | Base correcta; ampliable con SCA y detección de secretos |
| **CSRF deshabilitado** | `SecurityConfig` (todos) | **Correcto, no es un hallazgo.** APIs sin estado, sin cookies (`session.store-type: none`), autenticación por cabecera |
| **Ausencia de configuración CORS** | — | **Correcto, no es un hallazgo.** Consumo desde backends y app móvil, no desde navegador |
| **Apagado ordenado** | `server.shutdown: graceful` + `lifecycle.timeout-per-shutdown-phase: 2m` | Correcto |

---

## 14. Falsos positivos descartados

Coincidencias textuales analizadas y **descartadas** tras seguir el flujo completo:

| Patrón | Ubicación | Por qué NO es vulnerabilidad |
| ------ | --------- | ---------------------------- |
| `log.warn("request …: {}", request)` × 14 | `FacephiAdapter` (`beidentbiometric`) | **Añadido en v1.6.** Trece de las catorce llamadas registran DTO **sin `@Data` ni `@ToString`**: `toString()` es el de `Object` y el log recibe `Clase@hashcode`, no el contenido. Solo `FacephiAdapter:130` usa un DTO con `@Data` — esa sí es real y queda como SEC-012. Es el caso de manual de por qué hay que abrir el DTO antes de reportar una fuga en logs |
| `NoopHostnameVerifier` importado | `beemailboxes/RestTemplateConfig:9` | **Añadido en v1.6.** El import existe pero **no se usa**: el código instancia `DefaultHostnameVerifier` (línea 41). Un grep de `trust-all` marca este fichero; leerlo lo descarta. Recomendable eliminar el import para no volver a levantarlo |
| `getUsersQurable(key)` con el `key` del cliente en la URL | `QurableServiceAdapter` (`becustombeprogrm`) | **Añadido en v1.6.** No es SSRF: la base viene de configuración y el valor se interpola mediante plantilla `uri(".../{key}", key)`, que codifica el segmento. El solicitante no puede cambiar host, esquema ni ruta |
| `csrf.disable()` | `SecurityConfig` (11) | API stateless sin cookies de sesión; CSRF no aplica |
| Inyección SQL | `CmaRepository.java:18` | Único `@Query` del conjunto; usa binding `:documentNumber`, sin concatenación |
| Inyección en DynamoDB | `ExpressionBuilder.java` | Marcadores `#n`/`:v` con `expressionNames`/`expressionValues`; campo validado contra enum `FileField` |
| Inyección de comandos | — | No hay `Runtime.exec` ni `ProcessBuilder` en ningún proyecto |
| Deserialización insegura | — | No hay `ObjectInputStream`, `enableDefaultTyping` ni `activateDefaultTyping` |
| SSRF | `QurableServiceAdapter.java:137, 194` | Las URI usan plantillas (`{key}`) con valores codificados por `DefaultUriBuilderFactory`; las URL base provienen de configuración, no del request. **No se identificó ningún punto donde el solicitante controle el host de destino** |
| Path traversal en `getFileName` | `OTPServiceAdapter.java:143-146` | La ruta S3 procede de `FlujoEntity` (DynamoDB), no del request |
| `jwks.json` | `beclaims` | Contiene solo material público (`n`, `e`); no es exposición de secretos (SEC-045, informativo) |
| Race condition | `TokenService` (varios) | `synchronized` + doble comprobación correctamente aplicados; `volatile` en `becreditrisk` |
| Mass assignment | Delegates + mappers | Se usa MapStruct con mapeo explícito hacia entidades; no hay binding directo request→entidad |

---

## 15. Top 10 riesgos (probabilidad × impacto)

| # | Riesgo | Hallazgos | Prob. | Impacto | Justificación |
| - | ------ | --------- | ----- | ------- | ------------- |
| 1 | **Extracción de datos de clientes con un token legítimo (BOLA)** | SEC-002, SEC-001 | Alta | Crítico | Atraviesa el perímetro completo sin condiciones adicionales; CH-1 |
| 2 | **Bypass del segundo factor** | SEC-005, SEC-019, SEC-053 | Alta | Crítico | Tres vías independientes; CH-4. El limitador añadido en v1.5 cubre la generación pero no la validación, que es donde se fuerza el código |
| 3 | **Compromiso de proveedores por secretos versionados o compartidos entre entornos** | SEC-003, SEC-055 | Alta | Crítico | Las credenciales versionadas siguen comprometidas aunque se hayan externalizado; y el token de Qurable de producción se lee del almacén de desarrollo |
| 4 | **Fuga de credenciales y datos sensibles por logs** | SEC-007, SEC-005, SEC-011, SEC-012, SEC-013 | Alta | Alto | Cinco fugas independientes; el acceso al agregador de logs suele ser amplio |
| 5 | **Pérdida silenciosa de reclamos con confirmación falsa** | SEC-010 | Alta | Alto | No requiere atacante; impacto regulatorio directo (INDECOPI) |
| 6 | **Acceso lateral sin autenticación entre servicios** | SEC-001, SEC-021 | Media | Crítico | Requiere apoyo en el VPC, pero después no hay ningún control; CH-2 |
| 7 | **MITM en las integraciones con terceros** | SEC-004 | Media | Crítico | Seis servicios tras la corrección de `beemailboxes`; datos biométricos y credenciales en tránsito |
| 8 | **Salto de silo de datos por identidad IAM compartida** | SEC-054, SEC-043 | Media | Alto | Un pod comprometido alcanza el bucket documental o la tabla de OTP sin llamar a otro servicio; CH-6. *Sustituye a SEC-008, cerrado el 31-ago; el riesgo residual de aquel hallazgo es la purga pendiente en BD e historial* |
| 9 | **Denegación de servicio por ausencia de timeouts y límites** | SEC-016, SEC-019, SEC-020 | Media | Alto | Provocable con peticiones legítimas; afecta a OTP y correo |
| 10 | **Sustitución de documentos contractuales** | SEC-015, SEC-014, SEC-002 | Media | Alto | Impacto probatorio; CH-3 |

> **Revisión v1.5 (31-ago).** El orden se mantiene en su parte alta: los riesgos 1, 2, 4, 5 y 6 no han cambiado en nada. Los movimientos son: el riesgo 3 incorpora SEC-055; el riesgo 7 pasa de siete a seis servicios; el 8 se sustituye —SEC-008 está cerrado— por el salto de silo IAM (CH-6), que ha aparecido en esta revisión; y el 2 incorpora SEC-053, que documenta por qué el limitador añadido no cierra el bypass del 2FA.

> **Revisión v1.4.** Con los hallazgos SEC-047 a SEC-049, la cadena **CH-5** (extracción y destrucción del repositorio documental) pasa a competir por el primer puesto: es ejecutable de extremo a extremo con un token válido, sin ninguna condición adicional, y sus cinco hallazgos están en el mismo servicio. Al planificar, tratarla al nivel de CH-1.

---

## 16. Remediation Roadmap

### P0 — Inmediato (antes de cualquier despliegue a producción)

| Acción | Hallazgos | Esfuerzo |
| ------ | --------- | -------- |
| Rotar los secretos expuestos, coordinando con cada proveedor. **Sigue pendiente**: externalizarlos no los descompromete | SEC-003 | 2-3 días |
| Eliminar los dos valores por defecto que aún llevan credencial (`beclaims`, `bewatchscreening`) | SEC-003 | 1 h |
| Corregir `values-pro.yaml` de `becustombeprogrm` (`dev-` → `pro-`) y **rotar el token de Qurable** | SEC-055 | 2 h |
| Corregir los dos `role-arn` cruzados y crear los roles IRSA propios | SEC-054 | 1 día |
| ~~Eliminar `data.sql` y purgar el historial~~ **hecho**; queda purgar la BD y el historial de Git, y escalar al DPO | SEC-008 | 1 día |
| Eliminar el callback a `webhook.site` y externalizar `callbackUrl` | SEC-006 | 4 h |
| Eliminar los cuatro fail-open de `ClaimsAdapter` | SEC-010 | 4 h |
| Eliminar los registros de credenciales, tokens, OTP y clave AES | SEC-005, SEC-007 | 1 día |
| Restaurar la validación TLS con la CA de Netskope en el truststore | SEC-004 | 2-3 días |
| Implementar autorización de objeto en las 8 APIs afectadas | SEC-002 | 1-2 semanas |
| Activar `oauth2ResourceServer` con el JWKS de Cognito y `anyRequest().authenticated()` | SEC-001 | 1 semana |
| Rediseñar el flujo OTP (vínculo a sujeto, intentos, TTL, fuera del path) | SEC-005 | 1 semana |

### P1 — Próximo release

| Acción | Hallazgos |
| ------ | --------- |
| Añadir timeout al `WebClientConfig` de `becustombeprogrm` (el único que queda, y el único que además reintenta) | SEC-016 |
| Extender el rate limiter de OTP a la **validación** y acotar el registro de Resilience4j | SEC-053 |
| Corregir `getDocumentVersion` y eliminar `findAll()` del repositorio base | SEC-014 |
| Unificar la respuesta ante recurso inexistente en las tres operaciones | SEC-047 |
| Dejar de devolver el `ownerId` en el campo `name` de los metadatos | SEC-048 |
| Comprobar titularidad y auditar en el borrado de documentos | SEC-049 |
| Sanear la construcción de claves S3 y validar el MIME con Tika | SEC-015 |
| Separar el contrato interno y autenticar el tramo este-oeste | SEC-021 |
| Restringir el actuator y moverlo a `management.server.port` | SEC-022 |
| Corregir la emisión de JWT en `bedigitsignature` (claims, TTL de 20 s); `becustombeprogrm` ya está | SEC-023 |
| Confirmar con Arquitectura el estado del Lambda Authorizer | SEC-057 |
| Introducir `Idempotency-Key` y ajustar la política de retry | SEC-017, SEC-037 |
| Dejar de propagar el cuerpo de error del proveedor | SEC-018 |
| Añadir `maxLength`/`maxItems`/`pattern` a los contratos y validación de tamaño | SEC-020 |
| Aplicar rate limiting por sujeto y usage plans por `client_id` | SEC-019 |
| Migrar Contáctanos a HTTPS y validar el esquema en el arranque | SEC-009 |
| Eliminar `wiretap(true)` y fijar el nivel de la categoría | SEC-013 |
| Eliminar el volcado de documentos y biometría en logs | SEC-011, SEC-012 |

### P2 — Backlog de seguridad

SEC-056 (eliminar los valores de relleno en `pre`/`pro`), SEC-050 (acción fuera del path), SEC-051 (renombrar campos de `FileEntity`), SEC-024 (AES-GCM), SEC-027 (proxies de confianza), SEC-028 (manejadores de excepción), SEC-029 (`ddl-auto: validate` + migraciones), SEC-030 (`updateItem` — **la corrección actual deja el endpoint en 500**), SEC-031 (modelo de la tabla de firma), SEC-032 (eliminar el backdoor), SEC-033 (expiración de token), SEC-034 (unificación de dependencias), SEC-035 (`assert`), SEC-036 (endurecer XML), SEC-038 (log injection), SEC-039 (GSI y paginación), SEC-040 (semántica de `result`).

### P3 — Hardening

SEC-052 (alinear contratos), SEC-025 (Swagger por perfil), SEC-041 (eliminar `UtilsOtp`), SEC-042 (externalizar hostnames), SEC-043 (revisar el SA), SEC-044 (cabeceras de seguridad), SEC-045 (eliminar `jwks.json`), SEC-046 (alinear contratos).

**Transversales:**
* Incorporar `gitleaks`/`trufflehog` y SCA como *gates* bloqueantes en `security.yml`.
* Reemplazar los `SecurityConfigTest` actuales por tests de integración que verifiquen el 401.
* Aplicar `NetworkPolicy` entre los pods del namespace.
* Definir una configuración de referencia (`SecurityConfig`, `WebClientConfig`, `ControllerAdvice`) y aplicarla a los once proyectos, para evitar que la corrección se aplique de forma desigual.

---

## 17. Quick Wins

> ### 📘 Guía de ejecución: `GUIA_REMEDIACION_EH.md`
>
> Esta sección lista **qué** corregir. El anexo **`GUIA_REMEDIACION_EH.md`** dice **cómo**: 17 fichas con la ubicación exacta, el código actual, el código nuevo, el comando de verificación y el riesgo de cada cambio, agrupadas en cuatro PR.
>
> Cubre únicamente lo que se puede cerrar **sin decisiones de arquitectura ni de producto**. Su §0 explica por qué **SEC-002 (BOLA) no está incluido** y qué hace falta para desbloquearlo: saber qué claim del token de Cognito identifica al cliente. Aplicando la guía entera desaparecen unos nueve casos de prueba del informe del proveedor, pero **API1 seguirá reportándose**.


Correcciones de bajo esfuerzo y alto beneficio, ordenadas por relación impacto/esfuerzo:

> **Los tres primeros de esta lista se añaden en v1.6 y encabezan el orden por una razón: cada uno neutraliza un hallazgo Critical o High con un cambio de una a cinco líneas.**

| # | Acción | Esfuerzo | Hallazgo | Beneficio |
| - | ------ | -------- | -------- | --------- |
| **0a** | **`if ("Valid".equals(status))` en `OTPServiceAdapter:66`** | **2 min** | **SEC-005** | **La validación de OTP deja de aceptar cualquier código. Hoy `validOTP` ya calcula el veredicto correcto y el llamante lo tira** |
| **0b** | **Rechazar `keyValue` vacío o < 3 caracteres en `FileSearchMapper` y añadir `.limit(N)` al `ScanEnhancedRequest`** | **30 min** | **SEC-058, SEC-039** | **Convierte un volcado de una petición en una campaña ruidosa. Mitigación, no solución: la definitiva es SEC-002** |
| **0c** | **`log.info("Iniciando encriptacion… method={}", aesProperties.getSecret())` en `AesEncryptionService:33`** | **2 min** | **SEC-007** | **Deja de escribir la clave AES en el log. La etiqueta `method=` la hace fácil de pasar por alto en revisión** |
| 1 | Eliminar 6 líneas de log (OTP, password, token, clave AES, JWT, base64) | **15 min** | SEC-005, SEC-007, SEC-011 | Elimina cinco fugas de credenciales y datos |
| 2 | Sustituir `Constant.CALLBACK` por una propiedad de entorno | **30 min** | SEC-006 | Corta el envío de datos a un tercero público |
| 3 | Añadir `@ToString.Exclude` a 8 campos sensibles en DTO | **30 min** | SEC-007, SEC-012 | Cierra las fugas por `toString()` |
| 4 | Eliminar `.wiretap(true)` en 6 ficheros | **20 min** | SEC-013 | Elimina el riesgo latente de volcado completo |
| 5 | Cambiar `show-details: ALWAYS` por `when-authorized` y fijar `exposure.include` | **30 min** | SEC-022 | Reduce el reconocimiento de infraestructura |
| 6 | `springdoc.api-docs.enabled: false` en los perfiles pro/pre/cert | **20 min** | SEC-025 | Retira el contrato del plano lateral |
| 7 | Añadir timeouts a los 4 clientes que no los tienen | **1 h** | SEC-016 | Elimina el DoS por agotamiento de hilos |
| 8 | ~~Corregir `getDocumentVersion` para consultar por clave~~ | — | ~~SEC-014~~ | ✅ **Hecho en la entrega del 3-sep** |
| 9 | Sustituir `putIfAbsent` por `updateItem` en `patchConsent` | **20 min** | SEC-030 | Hace funcionar la revocación de consentimientos |
| 10 | Eliminar la rama `CONTRATO_CLIENTE` y `test.pdf` | **20 min** | SEC-032 | Retira código de pruebas de la ruta productiva |
| 11 | Sustituir los dos `assert` por comprobaciones explícitas | **15 min** | SEC-035 | Elimina dos NPE en el flujo de OTP |
| 12 | `ddl-auto: validate` y `sql.init.mode: never` en `beproducoffering` | **10 min** | SEC-029 | Impide cambios de esquema no controlados |
| 13 | Eliminar `UtilsOtp` (código muerto) | **10 min** | SEC-041 | Reduce superficie y evita su uso futuro |
| 14 | Añadir `maxItems: 10` al array de documentos de firma | **15 min** | SEC-019, SEC-020 | Corta la amplificación 1→2N |
| 15 | Devolver `fileName` en vez de `name` — **falta `searchMapper:49`** | **10 min** | SEC-048 | Corregido en `getMapper`; el método masivo sigue publicando el DNI |
| 16 | Unificar en 404 la respuesta ante documento inexistente | **1 h** | SEC-047 | Cierra el oráculo de enumeración |

**Total estimado: menos de una jornada de trabajo** para cerrar total o parcialmente 14 hallazgos, incluidos tres de severidad Critical.

---

## 18. Limitaciones de la revisión

Esta revisión es **estática y limitada al contenido de `E:\claude\Santander\APIs\codigo`**. Los siguientes elementos condicionan las conclusiones y **no han podido verificarse**:

**Sobre la arquitectura aportada.** El diagrama PRE/PROD se ha utilizado para calibrar severidades, pero **no se ha verificado su implementación real**. En concreto, no se ha comprobado:

* la configuración del **authorizer de Cognito** en el API Gateway: qué rutas cubre, si alguna queda sin él, y qué claims incluye el token emitido;
* las **reglas de Imperva y del AWS WAF**, sus cuotas y su comportamiento ante evasión;
* si el **API Gateway publica `/actuator/**`, `/swagger-ui.html` o `download_document_intern`** — se ha asumido que no, y de ahí la rebaja de SEC-025;
* la existencia de **NetworkPolicy** entre pods; la ausencia de evidencia es la razón por la que el riesgo este-oeste se considera abierto;
* la configuración de **PrivateLink y del NLB**, y si existe alguna ruta alternativa hacia los pods;
* la configuración de **Netskope** (inspección TLS, CA desplegada en las imágenes) — la hipótesis sobre la causa raíz de SEC-004 es plausible pero no confirmada.

**Sobre la plataforma AWS.** No se han verificado: políticas IAM de los roles asumidos (`AWS_IRSA_*`), políticas de bucket S3, cifrado en reposo (SSE-KMS) de S3, DynamoDB y RDS, versionado de objetos, TTL de las tablas, Security Groups, ACL de red, ni la configuración real de Secrets Manager.

**Sobre el código y el runtime.** No se han verificado: los valores reales de las variables de entorno en cada perfil, el comportamiento en ejecución (esta revisión no ejecutó ningún código ni invocó ningún endpoint), la retención y control de acceso del agregador de logs, ni el contenido del `santander-spring-boot-starter-*` (código del framework corporativo no incluido en el alcance), del que depende de forma relevante la valoración de SEC-001 y SEC-038.

**Sobre dependencias.** No se ejecutó análisis SCA. **Ningún CVE se afirma en este informe.** La §12 se basa únicamente en las versiones declaradas.

**Sobre los proveedores.** No se ha evaluado la postura de seguridad de FacePhi, Zytrust, Modellica, Gesintel, Celmedia, SKY, Qurable ni Contáctanos, ni se han validado sus contratos de integración.

**Principio aplicado:** no se ha asumido la existencia de ningún control del que no haya evidencia. Los controles que sí constan —el perímetro del diagrama, IRSA, Kubernetes Secrets, el contenedor sin privilegios— se han tenido en cuenta y figuran en la §13.

---

## 19. Verificación de cobertura

| Comprobación | Estado |
| ------------ | ------ |
| Se analizaron todos los proyectos en alcance? | Si, 11 de 11 (`beemailsend` y `lmauthorizer` excluidos: plantillas sin codigo de negocio, ver SEC-057) |
| Todos los controllers y delegates? | Si, 19 clases de entrada |
| Todos los endpoints? | Si, 42 operaciones declaradas en 11 contratos en alcance (eran 43 en v1.5 y 67 en v1.4); 54 contando la plantilla `beemailsend` |
| Spring Security? | Si, 10 `SecurityConfig` + `beemailboxes` sin ella |
| ¿Autenticación M2M? | Sí — 13 integraciones (§10) |
| ¿Autorización? | Sí — SEC-002, sin controles en 8 proyectos |
| ¿JWT / OAuth2 / API Keys? | Sí — SEC-005, SEC-007, SEC-023, SEC-031, SEC-033 |
| ¿TLS / mTLS? | Sí — SEC-004, SEC-009; sin mTLS en ninguna integración |
| ¿Todos los clientes HTTP? | Sí — 7 `WebClientConfig`, 1 `RestTemplateConfig`, 8 `AwsHttpClientConfig` |
| ¿URLs externas? | Sí — inventariadas en §10 |
| ¿Propagación de cabeceras? | Sí — SEC-021, SEC-026, SEC-027 |
| ¿Propagación de tokens? | Sí — no se reenvía el `Authorization` del consumidor; cada servicio obtiene el suyo (sin credential forwarding) |
| ¿Timeouts? | Sí — SEC-016 |
| ¿Retries? | Sí — SEC-017 |
| ¿Idempotencia? | Sí — SEC-037 |
| ¿Replay attacks? | Sí — SEC-006, SEC-037 |
| ¿SSRF? | Sí — analizado y **descartado** (§14) |
| ¿SQL Injection? | Sí — analizado y **descartado** (§14) |
| ¿Deserialización? | Sí — analizado y **descartado** (§14) |
| ¿XML / XXE? | Sí — SEC-036 (requiere validación) |
| ¿Criptografía? | Sí — SEC-023, SEC-024, SEC-041 |
| ¿Secretos? | Sí — SEC-003 (2 residuales tras la externalización), SEC-055 (cruce de entorno), SEC-056 (defectos de relleno) |
| ¿Logs? | Sí — SEC-005, SEC-007, SEC-011, SEC-012, SEC-013, SEC-038 |
| ¿Excepciones? | Sí — SEC-018, SEC-028 |
| ¿Dependencias? | Sí — §12, con la limitación declarada sobre CVE |
| Configuracion? | Si, los `application*.yml` de los 5 perfiles en los 11 proyectos, mas los `.gluon/cd` de despliegue (`values-cert/pre/pro`) |
| ¿Lógica de negocio? | Sí — SEC-010, SEC-030, SEC-032, SEC-040 |
| ¿Relaciones entre APIs? | Sí — SEC-021, §8 |
| ¿Cadenas de ataque? | Sí — 6 cadenas documentadas (§8); CH-5 reescrita en v1.6 |
| ¿Se eliminaron falsos positivos? | Sí — 13 patrones descartados con justificación (§14), 3 añadidos en v1.6 |
| ¿Cada hallazgo tiene evidencia? | Sí — archivo y línea verificados sobre el código |
| ¿Cada hallazgo tiene corrección concreta? | Sí — con código recomendado donde aplica |
| ¿Se re-escaneó con criterio de observabilidad externa? | Sí — v1.4, ver §22 y `EH_PREVIEW.md` |
| ¿Se re-verificaron los hallazgos previos contra el código actual? | Sí — v1.5 (los 52 del 24-ago) y **v1.6 (los 55 del 31-ago)**, uno a uno (§23, §24) |
| ¿Se verificaron los DTO antes de reportar fugas en logs? | Sí — v1.6, los 28 DTO de FacePhi uno a uno: 26 sin `@Data`/`@ToString` → SEC-012 atenuado y 13 coincidencias a falsos positivos (§14) |
| ¿Se verificaron las correcciones declaradas del ciclo anterior? | Sí — v1.6; **2 resultaron incompletas** (SEC-005, SEC-048), documentadas en §24.2 |
| ¿Se revisaron los datos persistidos, no solo los transmitidos? | Sí — v1.6, tablas DynamoDB de los 6 proyectos que persisten: SEC-031, SEC-051, SEC-059 |
| ¿Se revisaron los manifiestos de despliegue? | Sí — SEC-043, SEC-054, SEC-055 |
| ¿Identidad y permisos en la nube (IRSA)? | Sí — SEC-054; 9 de 11 servicios siguen la convención correcta |

---

---

## 20. Seguimiento de remediación

Registro de estado de los 55 hallazgos. **Esta es la sección que se actualiza en cada iteración**; el resto del informe solo cambia si aparece evidencia nueva o si un hallazgo se reevalúa.

Los estados de la revisión del 2026-08-31 se han asignado **verificando el código**, no por declaración del equipo: cada `CERRADO` de esta tabla corresponde a una comprobación documentada en el bloque de estado del hallazgo correspondiente.

### Convención de estados

| Estado | Significado |
| ------ | ----------- |
| `ABIERTO` | Sin trabajo iniciado |
| `EN CURSO` | Corrección en desarrollo |
| `EN REVISIÓN` | Corregido, pendiente de verificación sobre el código |
| `CERRADO` | Corregido y verificado sobre el código |
| `APLAZADO` | El hallazgo es válido y sigue abierto, pero su componente queda **fuera del alcance del ejercicio en curso**. No se elimina: conserva identificador, evidencia y remediación, y sale del cómputo de avance. Requiere anotar qué ejercicio lo excluye y cuándo se revisa |
| `ASUMIDO` | Riesgo aceptado formalmente; requiere justificación, responsable y fecha de revisión |
| `NO APLICA` | Descartado tras aportarse evidencia que invalida el hallazgo |

Para pasar a `CERRADO` se requiere: (a) la corrección visible en el código, (b) una prueba que falle si el defecto reaparece, y (c) la verificación anotada en la columna correspondiente. Un hallazgo corregido sin prueba de regresión se queda en `EN REVISIÓN`.

**`APLAZADO` no es una forma suave de cerrar.** Un hallazgo aplazado sigue contando como deuda: el código sigue desplegado y el defecto sigue explotable por quien tenga acceso a ese componente. La diferencia con `ABIERTO` es únicamente que no se mide contra el ejercicio en curso. Cuando el componente vuelva a alcance, el hallazgo vuelve a `ABIERTO` con su historial intacto — que es exactamente la razón de no borrarlo.

### Estado actual

**De los 56 hallazgos vivos, 47 están en `ABIERTO` y 9 en `APLAZADO`** (los de `becustombeprogrm`, `lmauthorizer` y la recepción de firma digital, fuera del alcance de este Ethical Hacking — ver §1.1). Aparte de ellos, **3 hallazgos de líneas base anteriores se han cerrado** (SEC-008 y SEC-026 el 31-ago; **SEC-014 el 3-sep**) y salen del recuento; se registran en la tabla siguiente. En este ciclo, además, 5 hallazgos han bajado de severidad, 1 ha reducido su alcance y **1 ha subido** (SEC-056).

| Estado | Critical | High | Medium | Low | Info | Total |
| ------ | -------: | ---: | -----: | --: | ---: | ----: |
| ABIERTO | 6 | 13 | 19 | 7 | 2 | **47** |
| APLAZADO | 1 | 1 | 6 | 0 | 1 | **9** |
| EN CURSO | 0 | 0 | 0 | 0 | 0 | 0 |
| EN REVISIÓN | 0 | 0 | 0 | 0 | 0 | 0 |
| CERRADO | 0 | 0 | 0 | 0 | 0 | 0 |
| ASUMIDO | 0 | 0 | 0 | 0 | 0 | 0 |

> **Por qué los cierres no figuran en esta tabla.** El recuento de 55 son los hallazgos vivos, y el Excel ejecutivo se genera de él; incluir ahí los cerrados haría que el porcentaje de avance del dashboard nunca partiera de cero. Los cierres tienen su propia tabla justo debajo.
>
> **Y por qué, en rigor, deberían estar en `EN REVISIÓN`.** El criterio de esta sección exige tres cosas para `CERRADO`: corrección en el código, prueba que falle si el defecto reaparece, y verificación anotada. La primera y la tercera están; **la prueba de regresión no existe en ninguno de los dos**. Se dan por cerrados porque la verificación se ha hecho sobre el código en esta auditoría, pero añadir esas dos pruebas es exactamente lo que impide que vuelvan como regresión en el próximo ciclo.

### Movimientos registrados el 2026-09-03

| ID | Movimiento | Detalle |
| -- | ---------- | ------- |
| SEC-014 | `ABIERTO` → **`CERRADO`** | `getDocumentVersion` usa `queryByPartitionKey(id)`. **Se aplicó literalmente el código recomendado en §5.** Pendiente: `findAll()` sigue existiendo en el repositorio base |
| SEC-012 | Medium ↓ | P2 | beidentbiometric | Token `tokenOcr` escrito al log en `FacephiAdapter:130` | `ABIERTO` |  |  | 2026-09-03 | 26 de 28 DTO sin `@ToString`: de 14 puntos de log queda 1 real |
| SEC-017 | Medium ↓ | P2 | becustombeprogrm | Reintentos sobre operaciones no idempotentes sin clave de i... | `ABIERTO` |  |  | 2026-09-03 | Retry acotado a 5xx/IO/timeout; falta clave de idempotencia |
| SEC-018 | Medium ↓ | P2 | becustombeprogrm, bedigitsignature | Cuerpo de error del proveedor propagado al consumidor | `ABIERTO` |  |  | 2026-09-03 | Cadena (a) cerrada en SKY; cadena (b) intacta en `bedigitsignature` |
| SEC-048 | Medium ↓ | P2 | bedocmanagement | El DNI del titular se devuelve en el campo `name` | `ABIERTO` |  |  | 2026-09-03 | Remediación incompleta: corregido en `getMapper`, no en `searchMapper` |
| SEC-049 | Low ↓ | P3 | bedocmanagement | Borrado sin verificación de titularidad ni existencia | `ABIERTO` |  |  | 2026-09-03 | Comprueba existencia y no es alcanzable desde el contrato |
| SEC-043 | Low | P3 | 4 proyectos | `automountServiceAccountToken: true` en despliegue productivo | `ABIERTO` |  |  | 2026-09-03 | Sin cambios: los mismos 4 en `true`; 5 no lo declaran y heredan el default |
| SEC-051 | Medium | P2 | 3 proyectos | Campos cruzados en `FileEntity`, `OtpEntity` y `Entity` | `ABIERTO` |  |  | 2026-09-03 | Patrón sistémico: la PK nunca coincide con el nombre del campo |
| SEC-056 | High ↑ | P1 | 5 proyectos | Valores de relleno como defecto de variables en `pre`/`pro` | `ABIERTO` |  |  | 2026-09-03 | **Agravado**: `bedigitsignature` pierde los perfiles y los rellenos llegan a `pro` |
| SEC-005 | Critical | P0 | beemailboxes | Bypass de OTP: sin vínculo a usuario, sin límite, OTP en pa... | `ABIERTO` |  |  | 2026-09-03 | **Remediación incompleta**: `validOTP` calcula el veredicto y `validCode` lo descarta |
| SEC-034 | Medium | P2 | Todos | Deriva de versiones; mezcla Netty 4.1.x/4.2.x | `ABIERTO` |  |  | 2026-09-03 | `beclaims` corregido; `bedatacomanagment` mezcla ahora tres líneas |
| SEC-058, SEC-059 | **Nuevos** | Volcado del inventario documental; PII en la tabla de auditoría biométrica |

### Movimientos registrados el 2026-08-31

| ID | Movimiento | Detalle |
| -- | ---------- | ------- |
| SEC-008 | `ABIERTO` → **`CERRADO`** | `data.sql` eliminado del árbol; sin referencias residuales. Pendiente: purga en BD e historial de Git |
| SEC-026 | `ABIERTO` → **`CERRADO`** | `application`/`channel` pasan a constantes de servidor; `society` eliminado del modelo |
| SEC-003 | Critical → **High** | Secretos externalizados salvo dos defectos en perfiles `local`. **La rotación sigue pendiente** |
| SEC-009 | High → **Medium** | `http://` solo persiste como defecto del perfil `local` |
| SEC-016 | High → **Medium** | Corregido en `beemailboxes` y `bedigitsignature`; queda `becustombeprogrm` |
| SEC-023 | High → **Medium** | Expiración y separación de claves corregidas en `becustombeprogrm`; `bedigitsignature` sin tocar |
| SEC-004 | Alcance 7 → 6 | `beemailboxes` corregido; sigue Critical |
| SEC-019 | Alcance parcial | Rate limiter en `beemailboxes`; sigue High. Genera SEC-053 |
| SEC-043 | Alcance 11 → 4 | Siete servicios a `false` |
| SEC-046 | 67/26 → 43/38 | Contratos recortados |
| SEC-052 | ~26 → 5 endpoints | Contratos recortados |
| SEC-034 | **Agravado** | La mezcla Netty 4.1/4.2 se extiende a `beclaims` |
| SEC-030 | Remediación incompleta | La comprobación añadida convierte todo `PATCH` válido en un 500 |
| SEC-053..057 | **Nuevos** | Tres de ellos derivados de los cambios de este ciclo |

### Inventario de acciones de remediación — entrega del 2026-09-03

Esta tabla responde a una pregunta distinta de la del recuento de hallazgos. **Hallazgos cerrados hay uno**; **acciones de remediación aplicadas al código hay ocho.** Confundir ambas cifras da una lectura injusta del trabajo del equipo en un sentido, y peligrosamente optimista en el otro.

> **Cómo se ha construido, y qué limitación tiene.** No existe una copia del árbol de código anterior con la que hacer diff: el directorio se sobrescribió con la entrega del 3-sep. La referencia utilizada son **las citas de código textuales de la v1.5 de este informe**, que sí registran el estado previo. Una acción solo se declara aquí cuando el fragmento citado en v1.5 ya no coincide con el código actual. En consecuencia, **pueden faltar acciones sobre código que v1.5 no citara literalmente** — por ejemplo, `DownloadDocumentValidator` existe hoy y v1.5 no lo menciona, pero eso no prueba que sea nuevo, y por eso no figura como acción.

| # | Acción verificada sobre el código | Proyecto | Hallazgo | Resultado | Alcance EH |
| - | --------------------------------- | -------- | -------- | --------- | ---------- |
| 1 | `getDocumentVersion` pasa de `findAll()` a `repository.queryByPartitionKey(id)` | bedocmanagement | SEC-014 | 🟢 **COMPLETA** — hallazgo cerrado | 🟢 En alcance |
| 2 | Los cuatro `new ExternalServiceException(...)` pasan `detail = null`; el cuerpo de SKY solo va a `log.error` | becustombeprogrm | SEC-018 (a) | 🟢 **COMPLETA** — para la integración SKY | ⏸️ Aplazado |
| 3 | `WebClientRetryPolicy.isRetryable` limita el reintento a 5xx, `IOException` y `TimeoutException` | becustombeprogrm | SEC-017 | 🟡 **PARCIAL** — sigue sin clave de idempotencia sobre un alta de usuario | ⏸️ Aplazado |
| 4 | `DocumentMapper.getMapper` devuelve `entity.getFileName()` en lugar de `entity.getName()` | bedocmanagement | SEC-048 | 🟡 **PARCIAL** — `searchMapper:49`, en el mismo fichero, sigue devolviendo el DNI | 🟢 En alcance |
| 5 | `deleteDocument` lanza `NotFoundException` en lugar de devolver 204 silenciosamente | bedocmanagement | SEC-049 | 🟡 **PARCIAL** — sigue sin verificar titularidad | 🟢 En alcance |
| 6 | El contrato deja de declarar `DELETE /documents/{id}` y `removeDocument` no implementa ningún delegate | bedocmanagement | SEC-049 | 🟡 **EFECTO COLATERAL FAVORABLE** — deja de ser alcanzable; el defecto sigue en el código | 🟢 En alcance |
| 7 | `JsonApiClient.validOTP` evalúa `status == "validated" && isValid()` en lugar de devolver el `message` del proveedor | beemailboxes | SEC-005 | 🔴 **INERTE** — el llamante sigue comprobando `!= null`; el comportamiento no cambia | 🟢 En alcance |
| 8 | Se eliminan `application-{local,cert,pre,pro}.yml` y se consolida en un único `application.yml` | bedigitsignature | SEC-056 | 🔴 **CONTRAPRODUCENTE** — los valores de relleno pasan a aplicar a producción | 🟢 En alcance |

**Distribución: 2 completas · 3 parciales · 1 efecto colateral favorable · 1 inerte · 1 contraproducente.**

**Y una consecuencia del recorte de alcance de v1.7 que conviene mirar de frente.** Las dos acciones completas de este ciclo son la #1 (`bedocmanagement`) y la #2 (`becustombeprogrm`). Al quedar `becustombeprogrm` fuera del Ethical Hacking, **dentro del alcance efectivo queda una sola remediación completa**: seis acciones en alcance, de las cuales 1 completa, 3 parciales, 1 inerte y 1 contraproducente. La lectura optimista del ciclo se apoyaba en buena medida en el componente que ahora no se prueba.

### Lo que NO se movió, y conviene decirlo con nombre

Tres cosas que en una primera lectura parecían mejoras de este ciclo y **no lo son**. Se verificaron contra el texto de v1.5 y ya estaban ahí:

| Elemento | Por qué no cuenta como acción de este ciclo |
| -------- | ------------------------------------------- |
| `BiometricInputPort.cleanData()` (truncado > 500 car.) | Ya figuraba en la tabla de controles existentes de v1.5 (§13) |
| `UploadDocumentValidator` | Ya se citaba textualmente en el detalle de SEC-020 en v1.5 |
| `automountServiceAccountToken: false` en tres proyectos | v1.5 ya registraba 7 servicios corregidos y 4 pendientes; el estado actual es **idéntico** |
| IV aleatorio con `SecureRandom` en `AesEncryptionService` | v1.5 ya lo daba por correcto en el detalle de SEC-024 |

Y los **cinco proyectos no refrescados** — `beclaims`, `becreditrisk`, `bedatacomanagment`, `beproducoffering`, `bewatchscreening` — no registran ninguna acción: su código es el mismo del 31-ago. Sus hallazgos (SEC-010 fail-open, SEC-029 `ddl-auto: update` en producción, SEC-030 `patchConsent`, SEC-033, SEC-040 `"Match Found"` constante, y los secretos residuales de SEC-003) siguen exactamente igual.

### Avance de remediación por severidad

Ninguna acción de este ciclo cierra un hallazgo Critical o High salvo SEC-014. El avance real, medido sobre hallazgos cerrados y no sobre acciones:

| Severidad | Vivos al 31-ago | Cerrados en el ciclo | Total trazable | Aplazados | **En alcance EH** | Avance |
| --------- | --------------: | -------------------: | -------------: | --------: | ----------------: | -----: |
| Critical | 7 | 0 | 7 | 1 | **6** | **0 %** |
| High | 18 | 1 | 14 | 1 | **13** | 5,6 % |
| Medium | 21 | 0 | 25 | 6 | **19** | 0 % |
| Low | 6 | 0 | 7 | 0 | **7** | 0 % |
| Info | 3 | 0 | 3 | 1 | **2** | 0 % |
| **Total** | **55** | **1** | **56** | **9** | **47** | **1,8 %** |

> La columna «Total trazable» no cuadra con la resta porque cinco hallazgos cambian de severidad y dos son nuevos; el desglose completo está en §24.1.
>
> **La columna «Aplazados» no es avance.** Ningún hallazgo aplazado se ha corregido: salen del alcance del ejercicio, no de la deuda. El porcentaje de avance se calcula sobre cerrados/total trazable precisamente para que aplazar no pueda inflarlo — si se midiera sobre el alcance efectivo, recortar el alcance subiría el indicador sin tocar una línea de código.
>
> Lo que sí es exacto y no admite matices: **de los siete hallazgos Critical, cero se han cerrado en los tres ciclos de auditoría**. Uno de ellos (SEC-006) queda ahora aplazado, con lo que el EH medirá seis.

### Hallazgos cerrados en este ciclo

Salen del recuento de hallazgos vivos porque ya no describen el estado del código. Se conservan aquí con su identificador para que el histórico siga siendo legible y para que la próxima auditoría pueda detectarlos si reaparecen (§21).

| ID | Severidad original | Hallazgo | Proyecto | Verificación |
| -- | ------------------ | -------- | -------- | ----------- |
| SEC-008 | Critical | Datos personales reales (DNI + PLAFT/PEP) en `data.sql` versionado | becreditrisk | **2026-08-31** — Fichero inexistente en todo el árbol; sin referencias en configuración. **Pendiente**: purga en BD e historial de Git |
| SEC-026 | Medium | Cabeceras `society`/`channel` del consumidor alimentan el motor de riesgo | becreditrisk | **2026-08-31** — `CreditRiskMapper:41-42` fija `application` y `channel` como constantes; `society` eliminado del modelo |
| SEC-014 | High | `GET /documents/{id}/versions` ignora el id y devuelve un scan completo | bedocmanagement | **2026-09-03** — `DocumentManagementAdapter:189-192` llama a `repository.queryByPartitionKey(id)`; `findAll()` ya no se invoca desde ninguna ruta productiva. **Pendiente**: eliminar `findAll()` del repositorio base y añadir autorización de titularidad (SEC-002) |

### Registro por hallazgo

| ID | Sev. | Prio. | Proyecto(s) | Hallazgo | Estado | Responsable | PR / commit | Verificado | Notas |
| -- | ---- | ----- | ----------- | -------- | ------ | ----------- | ----------- | ---------- | ----- |
| SEC-001 | Critical | P0 | Todos (11) | Autenticación y autorización desactivadas en todas las APIs | `ABIERTO` |  |  |  |  |
| SEC-002 | Critical | P0 | 8 proyectos | BOLA/IDOR sistémico sobre identificadores de negocio | `ABIERTO` |  |  |  |  |
| SEC-003 | High ↓ | P1 | beclaims, bewatchscreening | Secretos como valor por defecto de variables de entorno | `ABIERTO` |  |  | 2026-08-31 | Externalizados salvo 2 perfiles `local`. **Rotar igualmente** |
| SEC-004 | Critical | P0 | 6 proyectos | Validación de certificado TLS deshabilitada (trust-all) | `ABIERTO` |  |  | 2026-08-31 | `beemailboxes` corregido; replicar su patrón en los 6 restantes |
| SEC-005 | Critical | P0 | beemailboxes | Bypass de OTP: sin vínculo a usuario, sin límite, OTP en pa... | `ABIERTO` |  |  |  |  |
| SEC-006 | Critical | P0 | bedigitsignature | Callback de firma digital a `webhook.site` y token de callb... | `APLAZADO` |  |  | 2026-09-03 | Fuera del alcance del EH (bedigitsignature · recepción). Sigue abierto como deuda técnica. Callback: URL y token del webhook de retorno |
| SEC-007 | Critical | P0 | 4 proyectos | Credenciales, tokens y clave AES escritos en logs | `ABIERTO` |  |  |  |  |
| SEC-009 | Medium ↓ | P2 | beclaims | Credenciales por HTTP en claro a Contáctanos | `ABIERTO` |  |  | 2026-08-31 | Solo persiste como defecto del perfil `local` |
| SEC-010 | Critical | P0 | beclaims | Fail-open: se devuelven datos ficticios cuando falla el pro... | `ABIERTO` |  |  |  |  |
| SEC-011 | High | P1 | bedigitsignature | Documento PDF completo en base64 escrito al log | `ABIERTO` |  |  |  |  |
| SEC-012 | High | P1 | beidentbiometric | Tokens biométricos y datos de DNI escritos al log | `ABIERTO` |  |  |  |  |
| SEC-013 | High | P1 | 6 proyectos | `wiretap(true)`: tráfico HTTP completo (incl. `Authorizatio... | `ABIERTO` |  |  |  |  |
| SEC-015 | High | P1 | bedocmanagement | Clave S3 y `Content-Type` construidos con datos del cliente... | `ABIERTO` |  |  |  |  |
| SEC-016 | Medium ↓ | P2 | becustombeprogrm | Integraciones salientes sin timeout | `APLAZADO` |  |  | 2026-09-03 | Fuera del alcance del EH (becustombeprogrm). Sigue abierto como deuda técnica. Único proyecto que quedaba con el defecto |
| SEC-017 | High | P1 | becustombeprogrm | Reintentos sobre operaciones no idempotentes sin clave de i... | `APLAZADO` |  |  | 2026-09-03 | Fuera del alcance del EH (becustombeprogrm). Sigue abierto como deuda técnica. Reintentos sobre el alta en SKY |
| SEC-018 | High | P1 | becustombeprogrm, bedigitsignature | Cuerpo de error del proveedor propagado al consumidor | `ABIERTO` |  |  |  |  |
| SEC-019 | High | P1 | Todos | Sin rate limiting: amplificación de recursos y abuso de env... | `ABIERTO` |  |  | 2026-08-31 | Parcial en `beemailboxes`; ver SEC-053 |
| SEC-020 | High | P1 | 4 proyectos | Payloads base64 sin límite de tamaño ni validación | `ABIERTO` |  |  |  |  |
| SEC-021 | High | P1 | bedocmanagement ← bedigitsignature | Endpoint `download_document_intern` público y confianza tra... | `ABIERTO` |  |  |  |  |
| SEC-022 | High | P1 | Todos | Actuator expuesto sin autenticación con `show-details: ALWAYS` | `ABIERTO` |  |  |  |  |
| SEC-023 | Medium ↓ | P2 | becustombeprogrm, bedigitsignature | JWT M2M sin `iss`/`aud`/`jti`; 20 s en `bedigitsignature` | `APLAZADO` |  |  | 2026-09-03 | Fuera del alcance del EH (becustombeprogrm + bedigitsignature · recepción). Sigue abierto como deuda técnica. `JwtUtil` solo emite el token del callback |
| SEC-024 | Medium | P2 | becustombeprogrm | AES sin cifrado autenticado y transformación tomada de conf... | `APLAZADO` |  |  | 2026-09-03 | Fuera del alcance del EH (becustombeprogrm). Sigue abierto como deuda técnica. Cifrado del payload hacia SKY |
| SEC-025 | Low | P3 | Todos | Swagger UI y `/v3/api-docs` habilitados en todos los perfil... | `ABIERTO` |  |  |  |  |
| SEC-027 | Medium | P2 | Todos | `forward-headers-strategy: framework` sin proxy de confianz... | `ABIERTO` |  |  |  |  |
| SEC-028 | Medium | P2 | 5 proyectos | Excepciones no mapeadas producen 500 con posible detalle in... | `ABIERTO` |  |  |  |  |
| SEC-029 | Medium | P2 | beproducoffering | `ddl-auto: update` y `sql.init.mode: always` en producción | `ABIERTO` |  |  |  |  |
| SEC-030 | Medium | P2 | bedatacomanagment | `patchConsent`: remediación incompleta, todo `PATCH` válido da 500 | `ABIERTO` |  |  | 2026-08-31 | Se añadió la comprobación de existencia pero no se cambió la escritura |
| SEC-031 | Medium | P2 | bedigitsignature | JWT almacenado como partition key en DynamoDB | `APLAZADO` |  |  | 2026-09-03 | Fuera del alcance del EH (bedigitsignature · recepción). Sigue abierto como deuda técnica. El JWT se guarda para casar el callback entrante |
| SEC-032 | Medium | P2 | bedigitsignature | Backdoor de pruebas `CONTRATO_CLIENTE` devuelve un PDF del... | `ABIERTO` |  |  |  |  |
| SEC-033 | Medium | P2 | beclaims | Token cacheado sin expiración ni renovación | `ABIERTO` |  |  |  |  |
| SEC-034 | Medium ↑ | P2 | Todos | Deriva de versiones; mezcla Netty 4.1.x/4.2.x | `ABIERTO` |  |  | 2026-08-31 | **Agravado**: la mezcla se extiende a `beclaims` |
| SEC-035 | Medium | P2 | beemailboxes | `assert` usado para control de flujo (inactivo en runtime) | `ABIERTO` |  |  |  |  |
| SEC-036 | Medium | P2 | beemailboxes | `XmlMapper` sin endurecimiento explícito frente a DTD/entid... | `ABIERTO` |  |  |  |  |
| SEC-037 | Medium | P2 | bedigitsignature, becustombeprogrm, beemailboxes | Sin idempotencia ni anti-replay en operaciones sensibles | `ABIERTO` |  |  |  |  |
| SEC-038 | Medium | P2 | 6 proyectos | Datos externos escritos al log sin neutralizar (log injection) | `ABIERTO` |  |  |  |  |
| SEC-039 | Medium | P2 | bedocmanagement | `search_documents` ejecuta Scan completo de DynamoDB sin pa... | `ABIERTO` |  |  |  |  |
| SEC-040 | Medium | P2 | bewatchscreening | `validate_status` devuelve siempre `"Match Found"` | `ABIERTO` |  |  |  |  |
| SEC-041 | Low | P3 | beemailboxes | Generador de códigos con PRNG no criptográfico y espacio re... | `ABIERTO` |  |  |  |  |
| SEC-042 | Low | P3 | 3 proyectos | Endpoints internos y hostnames de BD revelados en el reposi... | `ABIERTO` |  |  |  |  |
| SEC-043 | Low | P3 | 4 proyectos | `automountServiceAccountToken: true` en despliegue productivo | `ABIERTO` |  |  | 2026-08-31 | 7 servicios corregidos; `beemailboxes` solo en `cert` |
| SEC-044 | Low | P3 | Todos | CSP definida para API JSON; falta política de cabeceras ade... | `ABIERTO` |  |  |  |  |
| SEC-045 | Info | P3 | beclaims | `jwks.json` con claves públicas presente pero no utilizado | `ABIERTO` |  |  |  |  |
| SEC-046 | Info | P3 | Todos | 43 operaciones declaradas frente a 38 implementadas | `ABIERTO` |  |  | 2026-08-31 | Contratos recortados; brecha residual de 5 |
| SEC-047 | High | P1 | bedocmanagement | Enumeración diferencial ante recurso inexistente | `ABIERTO` |  |  |  |  |
| SEC-048 | High | P1 | bedocmanagement | El DNI del titular se devuelve en el campo `name` | `ABIERTO` |  |  |  |  |
| SEC-049 | High | P1 | bedocmanagement | Borrado sin verificación de titularidad ni existencia | `ABIERTO` |  |  |  |  |
| SEC-050 | Medium | P2 | becustombeprogrm | El path variable determina el verbo HTTP saliente | `APLAZADO` |  |  | 2026-09-03 | Fuera del alcance del EH (becustombeprogrm). Sigue abierto como deuda técnica. Verbo HTTP hacia Qurable |
| SEC-051 | Medium | P2 | bedocmanagement | Campos cruzados en `FileEntity` | `ABIERTO` |  |  |  |  |
| SEC-052 | Low | P3 | bedocmanagement, beknowyocustomer, beemailboxes | Cinco endpoints declarados responden 501 | `ABIERTO` |  |  | 2026-08-31 | De ~26 a 5 |
| SEC-053 | High | P1 | beemailboxes | El rate limiter cubre la generación de OTP pero no la validación | `ABIERTO` |  |  | 2026-08-31 | Nuevo. Registro sin cota indexado por entrada del cliente |
| SEC-054 | High | P1 | becustombeprogrm, bedigitsignature | Dos servicios asumen el rol IAM de otro servicio | `ABIERTO` |  |  | 2026-08-31 | Nuevo. 9 de 11 siguen la convención correcta |
| SEC-055 | High | P1 | becustombeprogrm | El chart de `pro` lee un secreto de `dev-publickey-nexhub` | `APLAZADO` |  |  | 2026-09-03 | Fuera del alcance del EH (becustombeprogrm). Sigue abierto como deuda técnica. Secreto de Qurable en el chart de `pro` |
| SEC-056 | Medium | P2 | 4 proyectos | Valores de relleno como defecto de variables en `pre`/`pro` | `ABIERTO` |  |  | 2026-08-31 | Nuevo. Efecto colateral de la externalización de SEC-003 |
| SEC-057 | Info | P1 | lmauthorizer | El proyecto del Lambda Authorizer existe pero está vacío | `APLAZADO` |  |  | 2026-09-03 | Fuera del alcance del EH (lmauthorizer). Sigue abierto como deuda técnica. Proyecto completo fuera de alcance |
| SEC-058 | High | P1 | bedocmanagement | `search_documents` permite volcar el inventario documental completo | `ABIERTO` |  |  | 2026-09-03 | Nuevo. El caso de prueba de mayor valor para el Ethical Hacking |
| SEC-059 | Medium | P2 | beidentbiometric | La tabla de auditoría biométrica guarda DNI y tokens en claro | `ABIERTO` |  |  | 2026-09-03 | Nuevo. `cleanData` trunca >500 car., no clasifica por sensibilidad |

### Cómo actualizar este informe

1. **Al corregir un hallazgo:** cambiar su `Estado` en la tabla anterior, anotar responsable, PR y fecha de verificación. Actualizar el contador de avance y la tabla de estado.
2. **Si la corrección difiere de la recomendada:** anotarlo en `Notas` y, si el enfoque cambia el riesgo residual, ajustar el detalle del hallazgo en §5, §6 o §7.
3. **Si un hallazgo resulta inválido:** marcar `NO APLICA` con la evidencia en `Notas`, y añadirlo a §14 (Falsos positivos descartados) explicando por qué el análisis estático lo señaló.
4. **Si se acepta el riesgo:** marcar `ASUMIDO`, y registrar en `Notas` quién lo acepta, con qué justificación y en qué fecha se revisará.
5. **Al aparecer un hallazgo nuevo:** asignar el siguiente ID libre (SEC-047 en adelante), documentarlo con la misma estructura (ubicación, descripción, evidencia, flujo, source, sink, escenario, impacto, remediación) y añadirlo a §4, §9 y a esta tabla.
6. **Registrar el cambio** en el historial de versiones de la cabecera.

### Orden de ataque sugerido

Los quick wins de §17 son el mejor punto de partida: **menos de una jornada** para cerrar total o parcialmente 14 hallazgos, tres de ellos Critical. No requieren decisiones de arquitectura ni coordinación con terceros, así que pueden avanzar en paralelo al trabajo de fondo.

Después, por dependencias entre hallazgos:

```text
SEC-003 (rotar secretos)  ──► independiente, urgente, coordinar con proveedores
SEC-055 (secreto dev/pro) ──► corregir el chart Y rotar el token de Qurable
SEC-054 (rol IAM cruzado) ──► independiente, 2 ficheros + 2 roles nuevos
[SEC-008 (data.sql)       ──► CERRADO el 2026-08-31; queda la purga en BD e historial]
SEC-001 (validar JWT)     ──► habilita técnicamente a ──►  SEC-002 (autorización de objeto)
                                                            │
SEC-004 (CA de Netskope)  ──► independiente                 └──► cierra el riesgo #1 del §15
SEC-005 (rediseño OTP)    ──► independiente, requiere cambio de contrato
SEC-006 (callback)        ──► requiere definir la ruta de entrada con Arquitectura
```

`SEC-001` y `SEC-002` deben planificarse juntos: activar la validación del token sin implementar la autorización de objeto cierra el primero y deja el segundo intacto, que es el de mayor riesgo real según §15.


---

---

## 21. Línea base para comparativas

Este informe queda congelado como **línea base** en:

```text
security-baseline-2026-09-03-v1.6.json      ← vigente (56 hallazgos)
security-baseline-2026-08-31-v1.5.json      ← anterior (55 hallazgos)
security-baseline-2026-08-24-v1.4.json      ← (52 hallazgos)
security-baseline-2026-08-20-v1.2.json      ← primera (46 hallazgos)
```

Contiene los hallazgos vivos con una **huella estable** por hallazgo, calculada sobre CWE + proyecto + componente (sin números de línea) + términos del título. Esa huella es lo que permite emparejar hallazgos entre auditorías distintas.

**Por qué no se compara por ID.** Los identificadores `SEC-0NN` se asignan por orden de redacción. Si en la próxima auditoría aparece un hallazgo nuevo entre medias, la numeración se desplaza y `SEC-014` deja de referirse a lo mismo: comparar por ID generaría decenas de falsos "nuevos" y "resueltos". La huella sobrevive a la renumeración, a que el código cambie de línea y a reformulaciones del título. No incluye la severidad, porque su cambio es justamente lo que interesa detectar.

### Al ejecutar la próxima auditoría

```bash
# 1. Congelar la nueva línea base
python snapshot_baseline.py SECURITY_CODE_REVIEW.md security-baseline-<fecha>.json

# 2. Comparar contra la vigente
python compare_scans.py security-baseline-2026-09-03-v1.6.json security-baseline-<fecha>.json --md comparativa.md
```

> **Aviso aprendido en esta iteración.** La huella se calcula sobre CWE + proyecto + componente + términos del título. Reescribir cualquiera de esos campos —aunque sea para reflejar mejor la realidad, como cambiar «7 proyectos» por «6 proyectos»— rompe el emparejamiento y produce un diff falso: en la primera pasada de v1.5 el comparador reportó 19 nuevos y 14 resueltos donde en realidad había 5 y 2. Por eso la tabla de §4 conserva la redacción de v1.4 en esos tres campos y registra los cambios en la columna `Δ`. Si un hallazgo cambia hasta el punto de necesitar otro título, lo correcto es cerrarlo y abrir uno nuevo, no reescribirlo.
>
> **Y volvió a pasar en v1.6.** Al redactar esta versión se actualizaron los campos `proyecto` y `componente` de cuatro hallazgos para reflejar mejor la realidad — SEC-051 de «bedocmanagement» a «3 proyectos», SEC-056 de «4 proyectos» a «5», y las ubicaciones de SEC-017 y SEC-018. El comparador respondió con **6 nuevos y 5 resueltos** donde en realidad había 2 y 1: los cuatro aparecían simultáneamente en ambas listas. Restaurando los campos originales y llevando el detalle a la columna `Δ`, la comparativa quedó en 2 nuevos, 1 resuelto, 1 agravado, 5 atenuados y 0 regresiones.
>
> La lección operativa, ya por segunda vez: **el impulso de «mejorar la redacción» de esos tres campos es constante, y siempre rompe la comparación**. Conviene contrastar el resultado de `compare_scans.py` con el análisis manual antes de darlo por bueno: una cifra de nuevos o resueltos más alta de lo esperado casi nunca significa que el código haya cambiado tanto.

El resultado clasifica cada hallazgo en `RESUELTO`, `NUEVO`, `PERSISTE`, `AGRAVADO`, `ATENUADO` o `REGRESION`, y produce un anexo listo para incorporar al informe nuevo.

### Qué vigilar

**`REGRESION`** — un hallazgo cerrado que reaparece. Es la razón de ser de este mecanismo: en un informe aislado parecería un hallazgo más, y solo la comparación lo delata. Suele indicar que la corrección no llegó a desplegarse, que se revirtió en un merge, o que se aplicó a un componente y no a los demás que compartían el defecto.

**`RESUELTO`** — conviene confirmar la causa antes de anotarlo como logro: un hallazgo también desaparece si el componente salió del alcance o si el código se movió.

Los scripts están en la skill `security-code-review` (`~/.claude/skills/security-code-review/scripts/`).


---

---

## 22. Anexo: vista previa del Ethical Hacking

Documento complementario: **`EH_PREVIEW.md`** (mismo directorio).

Ante la confirmación de que el Ethical Hacking será de **caja negra, sin revisión de código y a través del API Gateway con credenciales entregadas**, se re-escaneó el código con un criterio distinto al de esta auditoría: no *¿qué está mal?* sino **¿qué es observable desde fuera?**.

El anexo contiene:

* El **modelo de atacante** asumido y sus implicaciones.
* El mapeo de los hallazgos contra **OWASP API Security Top 10 2023**, el marco que previsiblemente usará el proveedor. Nueve de las diez categorías tienen al menos un hallazgo asociado; la única limpia es SSRF, verificada y descartada.
* **18 casos de prueba** concretos con la petición y el resultado esperado. **CP-18, añadido el 3-sep, es el de mayor valor de la lista**: una petición autenticada a `POST /search_documents` con `keyValue: ""` devuelve el inventario documental completo y el DNI de cada titular (SEC-058).
* La lista de **qué no verá** el proveedor y por qué.
* Priorización previa a la prueba.

### Dos conclusiones que afectan a la lectura de este informe

**1. SEC-001 quedará enmascarado.** Con el API Gateway y Cognito delante, las pruebas de autenticación —sin cabecera, token expirado, firma alterada— se detendrán en el perímetro. El proveedor no detectará que el backend no valida el token, porque nunca le llegará una petición sin token válido.

Esto tiene una consecuencia de gobierno: si el informe del Ethical Hacking concluye *"autenticación correcta"*, estará certificando una capa que no existe. Conviene que el alcance quede documentado explícitamente en su informe.

**2. Un resultado limpio no equivale a código seguro.** De los 55 hallazgos, alrededor de 22 son observables desde fuera. Los 33 restantes —secretos versionados, validación TLS anulada, credenciales en logs, datos personales en `data.sql`, dependencias— solo se detectan con acceso al código, que es justamente el alcance de esta auditoría y no el de la prueba externa.

### Recomendación sobre el alcance

Plantear a Arquitectura la inclusión de un **escenario de red interna o de contenedor comprometido**. Sin él, SEC-001 y SEC-021 no se prueban, y son los dos hallazgos sobre los que se apoya el resto del modelo de confianza. Es práctica habitual en el sector.


---

*Informe generado mediante revisión estática del código fuente. Las credenciales identificadas se reportan enmascaradas y no han sido utilizadas. No se modificó ningún archivo del código fuente; el único fichero creado es este informe.*

---

## 23. Comparativa con la auditoría anterior (v1.4 → v1.5)

Generada con `compare_scans.py` sobre las dos líneas base congeladas. El emparejamiento no usa los identificadores `SEC-0NN`, sino la huella descrita en §21.

```text
Anterior: security-baseline-2026-08-24-v1.4.json   (52 hallazgos)
Actual:   security-baseline-2026-08-31-v1.5.json   (55 hallazgos)
```

| Categoría | N.º | Severidades |
| --------- | --: | ----------- |
| **REGRESIONES** | **0** | — |
| Resueltos | 2 | Critical 1, Medium 1 |
| Nuevos | 5 | High 3, Medium 1, Info 1 |
| Atenuados | 4 | High→Medium 3, Critical→High 1 |
| Agravados | 0 | — |
| Persisten | 46 | Critical 7, High 14, Medium 17, Low 6, Info 2 |

**Cero regresiones** es el dato positivo más sólido del ciclo: ningún defecto dado por corregido ha reaparecido.

### 23.1 Lo que el comparador no ve, y hay que leer aquí

El comparador clasifica por severidad. Cinco movimientos de este ciclo cambian el **alcance** sin cambiar la severidad, y por eso figuran como `PERSISTE`:

| ID | Cambio real | Severidad |
| -- | ----------- | --------- |
| SEC-004 | TLS trust-all: 7 → **6** proyectos (`beemailboxes` corregido) | Se mantiene Critical: sigue en los seis que hablan con Modellica, FacePhi, Gesintel, SKY y Qurable |
| SEC-019 | Primer rate limiter del conjunto, en `beemailboxes` | Se mantiene High: cubre 1 de 11 servicios y una de las dos operaciones sensibles |
| SEC-043 | `automountServiceAccountToken`: 11 → **4** proyectos | Se mantiene Low |
| SEC-046 | Operaciones declaradas/implementadas: 67/26 → **43/38** | Se mantiene Info |
| SEC-052 | Endpoints que responden 501: ~26 → **5** | Se mantiene Low |

Y dos movimientos que empeoran sin subir de severidad:

| ID | Qué pasó |
| -- | -------- |
| **SEC-034** | La mezcla de líneas de Netty (4.1.x + 4.2.x en el mismo classpath) ya no está solo en `bedatacomanagment`: ahora también en `beclaims`. Sigue siendo Medium, pero afecta al doble de servicios |
| **SEC-030** | Se intentó corregir y el resultado es peor de observar: se añadió la comprobación de existencia pero se conservó `putIfAbsent`, de modo que **toda actualización de consentimiento válida termina en 500** |

### 23.2 Los cinco nuevos

Tres de los cinco **no existían antes de las correcciones de este ciclo**. No son defectos que se pasaran por alto en agosto: son consecuencia de cómo se aplicaron los arreglos.

| ID | Sev. | Hallazgo | Origen |
| -- | ---- | -------- | ------ |
| SEC-053 | High | El rate limiter cubre la generación de OTP pero no la validación; su registro crece sin cota | **Derivado** del control añadido para SEC-019 |
| SEC-054 | High | `becustombeprogrm` y `bedigitsignature` asumen el rol IAM de otro servicio | Preexistente, detectado al revisar la configuración externalizada |
| SEC-055 | High | El chart de `pro` de `becustombeprogrm` lee un secreto de `dev-publickey-nexhub` | **Derivado** de la migración de secretos de SEC-003 |
| SEC-056 | Medium | Valores de relleno (`xx`, `test`, `12`) como defecto de variables en `pre`/`pro` | **Derivado** de la externalización de SEC-003 |
| SEC-057 | Info | El proyecto del Lambda Authorizer existe pero está vacío | Proyecto nuevo en el árbol |

### 23.3 Lectura

**Lo que ha funcionado.** El equipo ha cerrado el hallazgo con mayor exposición regulatoria (SEC-008, datos personales versionados), ha sacado los secretos del árbol de fuentes, ha corregido TLS y timeouts en `beemailboxes`, ha añadido el primer control de caudal del programa y ha recortado los contratos a lo implementado — que era el hallazgo de inventario (API9) que un pentester habría usado como mapa. Nada de esto es cosmético.

**Lo que no se ha movido.** Ninguno de los cuatro defectos estructurales:

| ID | Estado el 24-ago | Estado el 31-ago |
| -- | ---------------- | ---------------- |
| SEC-001 — autenticación desactivada | 11/11 servicios | **11/11 servicios**, sin un solo `oauth2ResourceServer` en el código base |
| SEC-002 — sin autorización de objeto | 8 proyectos | **8 proyectos**, ningún delegate lee el token |
| SEC-005 — OTP sin vínculo al usuario | `status != null` | **`status != null`**, y ahora sabemos que además no tiene límite de intentos (SEC-053) |
| SEC-006 — callback a `webhook.site` | `Constant:64` | **`Constant:64`**, con el mismo token literal `jwt` |

El trabajo se ha concentrado en lo mecánico —configuración, versiones, contratos— y no ha tocado lo que exige diseño. Es el orden inverso al del §16, y explica por qué el recuento de Critical baja de 9 a 7 mientras el riesgo real apenas se mueve.

**Un patrón que conviene romper.** Tres correcciones de este ciclo se aplicaron a un componente y no a los demás que compartían el defecto:

* `becustombeprogrm` corrigió el TTL del JWT; `bedigitsignature` conserva los 20 segundos (SEC-023).
* `beemailboxes` corrigió `automountServiceAccountToken` en `cert` y lo dejó en `pre` y `pro` (SEC-043).
* `beemailboxes` corrigió TLS y timeouts; los otros seis servicios con el mismo `WebClientConfig` no (SEC-004, SEC-016).

Ese patrón es la causa habitual de las regresiones que este mecanismo existe para detectar. La recomendación transversal de §16 —una configuración de referencia común aplicada a los once proyectos— deja de ser una mejora deseable y pasa a ser la condición para que el próximo ciclo no repita esto.

**Y una sobre el método.** Tres de los cinco hallazgos nuevos nacen de las propias correcciones. No es un reproche al equipo: es lo normal cuando se cambia configuración sensible sin una verificación posterior. La conclusión práctica es que **cada corrección de un hallazgo P0/P1 debería llevar asociada su prueba**, y que conviene re-verificar tras cada tanda de arreglos en lugar de esperar a la siguiente auditoría completa.

---


## 24. Comparativa con la auditoría anterior (v1.5 → v1.6)

Generada con `compare_scans.py` sobre las líneas base `security-baseline-2026-08-31-v1.5.json` y `security-baseline-2026-09-03-v1.6.json`. El anexo completo está en `comparativa-v15-v16.md`.

| | v1.5 (31-ago) | v1.6 (3-sep) |
| --- | ---: | ---: |
| Hallazgos | 55 | **56** |
| Critical | 7 | **7** (=) |
| High | 18 | **14** (−4) |
| Medium | 21 | **25** (+4) |
| Low | 6 | **7** (+1) |
| Info | 3 | **3** (=) |

| Categoría | N.º | Severidades |
| --------- | --: | ----------- |
| **REGRESIÓN** | **0** | — |
| Resueltos | 1 | High 1 |
| Nuevos | 2 | High 1, Medium 1 |
| Agravados | 1 | High 1 |
| Atenuados | 5 | Medium 4, Low 1 |
| Persisten | 48 | Critical 7, High 12, Medium 20, Low 6, Info 3 |

### 24.1 Movimiento por movimiento

**Resuelto (1)**

| ID | Sev. anterior | Hallazgo | Verificación |
| -- | ------------- | -------- | ------------ |
| SEC-014 | High | `GET /documents/{id}/versions` ignoraba el id y devolvía un scan completo | `DocumentManagementAdapter:188-192` llama a `queryByPartitionKey(id)`. Se aplicó **literalmente el código recomendado en §5**. Confirmado por causa, no por ausencia: el método existe, el endpoint sigue publicado y ha cambiado su implementación |

**Atenuados (5)**

| ID | Antes | Ahora | Motivo |
| -- | ----- | ----- | ------ |
| SEC-012 | High | Medium | **Verificación más precisa por nuestra parte, no corrección del equipo.** 26 de 28 DTO de FacePhi carecen de `@Data`/`@ToString`: sus 13 `log.warn(request)` imprimen `Clase@hash`. Queda 1 punto real |
| SEC-017 | High | Medium | `WebClientRetryPolicy` excluye los 4xx del reintento |
| SEC-018 | High | Medium | Cadena (a) cerrada: SKY pasa `detail=null` y códigos `TL*`. Cadena (b), `bedigitsignature`, intacta |
| SEC-048 | High | Medium | `getMapper` corregido; el vector individual desaparece |
| SEC-049 | High | Low | Comprueba existencia y deja de ser alcanzable desde el contrato |

**Agravado (1)**

| ID | Antes | Ahora | Motivo |
| -- | ----- | ----- | ------ |
| SEC-056 | Medium | High | `bedigitsignature` elimina `application-{local,cert,pre,pro}.yml`. Los valores de relleno `${SEC_SKY_JWT_SECRET:12}`, `${AWS_TABLE_REGION:xx}` y `${AWS_IRSA_BEDOCMANAGEMENT:test}` dejan de vivir en perfiles no productivos y pasan a ser **el valor por defecto de producción** |

**Nuevos (2)**

| ID | Sev. | Hallazgo | Origen |
| -- | ---- | -------- | ------ |
| SEC-058 | High | `search_documents` permite volcar el inventario documental completo con el DNI del titular | **Preexistente, no detectado antes.** No nace de ningún cambio: es la composición de SEC-002, SEC-039 y SEC-048, que estaban reportados por separado. La revisión anterior los trató como tres defectos independientes y no siguió el flujo hasta ver que juntos forman una primitiva de volcado en una sola petición |
| SEC-059 | Medium | La tabla de auditoría biométrica guarda DNI y tokens de sesión en claro, sin TTL | **Preexistente**, aflorado al verificar SEC-012: al comprobar que los logs no filtran biometría, el rastro llevó a dónde sí acaba el contenido del request |

### 24.2 Las dos remediaciones incompletas

Ninguna de las dos aparece en la clasificación del comparador —ambas quedan como `PERSISTE`— y son, sin embargo, lo más importante de este ciclo.

| ID | Qué se corrigió | Por qué no surtió efecto |
| -- | --------------- | ------------------------ |
| **SEC-005** | `JsonApiClient.validOTP` pasó de devolver el `message` del proveedor a evaluar `status == "validated" && isValid()`, devolviendo `"Valid"` o `"Invalid"` | El llamante, `OTPServiceAdapter:66`, **no se tocó**: sigue comprobando `status != null`. Como el método ya nunca devuelve `null`, la rama de error es código muerto y **toda validación de OTP responde `PROCESSED`**, incluida la de un código incorrecto |
| **SEC-048** | `DocumentMapper.getMapper` dejó de devolver el DNI del titular en el campo `name` | `searchMapper`, en el mismo fichero, sigue haciéndolo — y es el método que devuelve **muchos** registros por llamada, no uno. La exposición se desplazó del endpoint menor al mayor |

**Por qué esto merece una sección propia.** Una vulnerabilidad visible se corrige tarde o temprano. Una vulnerabilidad **enmascarada por una corrección aparente** sobrevive a las revisiones siguientes, porque el `git diff` del fichero corregido convence a cualquier revisor. En el caso de SEC-005, quien lea el cambio de `JsonApiClient` concluirá razonablemente que el bypass de OTP está resuelto; hace falta abrir un segundo fichero, que no aparece en ese diff, para ver que no lo está.

Es la tercera vez que este patrón aparece: en v1.5 fue SEC-030 (se añadió la comprobación de existencia y se conservó `putIfAbsent`, dejando todo `PATCH` válido en 500). La causa es siempre la misma —**se corrige el punto señalado en el informe sin recorrer el flujo completo**— y la contramedida también: una prueba que ejercite el caso de abuso de extremo a extremo, no una inspección del fichero modificado.

### 24.3 Lectura

**Lo que ha funcionado.** Se han verificado **ocho acciones de remediación** sobre el código de esta entrega (inventario completo y método de verificación en §20). Dos son completas: `bedocmanagement` corrigió el listado de versiones aplicando el código recomendado (SEC-014), y `becustombeprogrm` cortó la salida del cuerpo de error de SKY hacia el consumidor pasando `detail = null` en los cuatro puntos (SEC-018 a). Tres son parciales pero van en la dirección correcta: el filtro de reintentos, el `getMapper` y la comprobación de existencia en el borrado.

Es además el **primer ciclo sin hallazgos nuevos derivados de las propias correcciones**: los dos nuevos de v1.6 son preexistentes que la revisión anterior no vio, frente a los tres de v1.5 que nacían de los arreglos.

**Y lo que no era lo que parecía.** Cuatro elementos que en una primera lectura se leían como mejoras de este ciclo ya estaban en v1.5 y se han retirado del balance tras contrastarlos con el texto de aquella versión: `cleanData`, `UploadDocumentValidator`, el IV aleatorio de AES y los tres `automountServiceAccountToken: false` — este último, además, con el estado **idéntico** al de v1.5 (mismos 4 en `true`). Queda anotado en §20 porque un balance inflado hace tanto daño como uno injusto: la siguiente auditoría lo hereda como línea de partida.

**Lo que no se ha movido.** Ninguno de los cuatro defectos estructurales, por tercera revisión consecutiva:

| ID | 24-ago | 31-ago | 3-sep |
| -- | ------ | ------ | ----- |
| SEC-001 — autenticación desactivada | 11/11 | 11/11 | **11/11** · `santander.security.enabled: false` + `white-list: /**` + `anyRequest().permitAll()`; ni un `oauth2ResourceServer` en 682 ficheros |
| SEC-002 — sin autorización de objeto | 8 proyectos | 8 proyectos | **8 proyectos** · ningún delegate lee el token |
| SEC-005 — OTP sin vínculo al usuario | `status != null` | `status != null` | **`status != null`**, ahora con una corrección inerte delante |
| SEC-006 — callback a `webhook.site` | `Constant:64` | `Constant:64` | **`Constant:64`**, con el mismo `Bearer jwt` literal por el `replace("JWT", jwt)` que nunca casa |

**El dato que resume el ciclo.** Se cerró SEC-014 y se neutralizó SEC-049 —los dos extremos de la cadena de ataque CH-5— y la cadena **sigue viva y es más corta que antes**: donde en v1.5 hacían falta tres peticiones y un oráculo de enumeración, hoy basta una (§8, CH-5). Mientras SEC-002 no exista, cerrar endpoints uno a uno desplaza la cadena al siguiente en lugar de romperla.

**Recomendación de método para el próximo ciclo.** Dos cambios concretos, ambos derivados de lo observado aquí:

1. **Cada corrección de un hallazgo P0/P1 debe llevar su prueba de abuso**, no su prueba unitaria. Para SEC-005: un test que envíe un OTP incorrecto y exija `ERROR`. Habría fallado en verde el mismo día en que se escribió la corrección de `validOTP`.
2. **Re-verificar la cadena, no el fichero.** Las dos remediaciones incompletas de este ciclo y la de v1.5 se habrían detectado recorriendo el flujo de extremo a extremo una sola vez tras el arreglo.

---


## 25. Revisión de alcance v1.6 → v1.7

v1.7 **no es un re-escaneo**: el código es el mismo que analizó v1.6. Lo único que cambia es qué entra en el Ethical Hacking. La comparativa automática lo confirma y sirve como control de que no se ha colado ningún cambio de contenido:

```text
Anterior: v1.6  (56 hallazgos)      Actual: v1.7  (56 hallazgos)
  REGRESIONES  0 · Nuevos 0 · Resueltos 0 · Agravados 0 · Atenuados 0
  Persisten   56   Critical 7, High 14, Medium 25, Low 7, Info 3
```

Cero movimientos en las seis categorías es exactamente el resultado esperado: **aplazar no es corregir**, y el mecanismo de comparación no debe registrarlo como si lo fuera. Anexo completo en `comparativa-v16-v17.md`.

### 25.1 Qué queda fuera y por qué

| Ámbito excluido | Alcance de la exclusión | Hallazgos aplazados |
| --------------- | ----------------------- | ------------------- |
| `cpe-nxhbsc-becustombeprogrm` (SKY, Qurable) | Componente completo | SEC-016, SEC-017, SEC-024, SEC-050, SEC-055 |
| `cpe-nxhbsc-lmauthorizer` | Proyecto completo | SEC-057 |
| `cpe-nxhbsc-bedigitsignature` | **Solo la recepción** (callback de retorno). El API de solicitud de firma sí entra | SEC-006, SEC-023, SEC-031 |

**Total: 9 aplazados · 47 en alcance · 56 con trazabilidad.**

### 25.2 Tres cosas que el aplazamiento no cambia

**1. Los defectos siguen ahí.** Ningún hallazgo aplazado se ha corregido. El código sigue desplegado y sigue siendo explotable por quien tenga acceso a esos componentes. Si el Ethical Hacking sale limpio, no dirá nada sobre ellos — igual que no dirá nada sobre SEC-001 (§22).

**2. El indicador de avance no sube.** El porcentaje de la hoja `Remediacion` del Excel se calcula sobre el **total trazable (56)**, no sobre el alcance (47). Es deliberado: si se midiera sobre el alcance, recortarlo subiría el avance sin tocar una línea de código, que es precisamente la métrica que no queremos construir.

**3. Hay un efecto que cruza la frontera, y conviene tenerlo presente.** SEC-006 se aplaza por ser recepción, pero la URL de retorno hacia `webhook.site` **la envía el API de solicitud, que sí está en alcance**. El proveedor del EH no lo verá —nunca iba a verlo— pero el documento firmado puede acabar en un servicio público de terceros a partir de una llamada al endpoint que sí se va a probar. La corrección cuesta una propiedad de entorno y está en §17.

### 25.3 Cuando estos componentes vuelvan a alcance

Los nueve hallazgos conservan identificador, evidencia, severidad y remediación. Basta con devolverlos a `ABIERTO` en §20 y volver a ejecutar los scripts de la cadena del Excel. No reaparecerán como hallazgos nuevos en la comparativa, que es exactamente la razón de haberlos aplazado en lugar de borrarlos: **su huella sigue en la línea base**, y `security-baseline-2026-09-03-v1.7.json` registra además el alcance del ejercicio en el bloque `alcance_ejercicio`.

> **Nota sobre las herramientas.** `snapshot_baseline.py` y `build_exec_xlsx.py` de la skill no conocen el estado `APLAZADO` y lo leen como `ABIERTO`. El script local `aplicar_alcance_eh.py` corrige las tres salidas afectadas (hoja Seguimiento, columna EH y línea base JSON) y debe ejecutarse **después** de ellos. La cadena completa es: `build_exec_xlsx` → `aplicar_columna_eh` → `aplicar_alcance_eh` → `aplicar_hoja_remediacion` → `recalc_excel_win`.

---
