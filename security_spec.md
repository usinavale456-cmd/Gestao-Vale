# Security Specification & Test-Driven Design (TDD)
## System: Weekly Agroindustrial Management Dashboard

This security specifications document outlines the zero-trust architecture designed to protect production, costs, quality, goals, and user directories in the agroindustrial weekly platform.

---

### 1. Core Data Invariants

1. **Role-Based Access Control (RBAC)**:
   - **Gestor (Manager)**: Full access to configure goals (`metas`), manage user profiles (`usuarios`), and read/write production/costs/quality data.
   - **Operador (Operator)**: Authenticated user authorized to input weekly logs (`producao`, `custos`, `qualidade`). Restricted from editing goals (`metas`) and managing other users.
   - **Analista (Analyst)**: Read-only access to dashboards, reports, and comparisons. Completely restricted from any state modification.

2. **Schema Integrity and Boundaries**:
   - `cana_moida` must be non-negative.
   - `extracao` (mill extraction efficiency) must be between 0% and 100%.
   - `perdas_art` (sucrose losses ART) must be between 0% and 100%.
   - `atr` (Açúcares Totais Recuperáveis) must be between 0 and 300 kg/t.
   - Timestamps `updatedAt` must leverage `request.time` exactly.
   - Document IDs must match the format `isValidId` and be strictly bounded to prevent resource exhaustion.

3. **Immutability Rules**:
   - The indicator week (`semana`) is immutable after creation.
   - Profile email and user IDs are immutable.

---

### 2. The "Dirty Dozen" Malicious Payloads

The following payloads attempt to violate security boundaries, bypass role hierarchies, or pollute the database. The Firestore rules MUST reject each and every one of these transfers with a `PERMISSION_DENIED` exception.

#### Payload 1: Privilege Escalation Attack (By-passing user role check)
* **Goal**: A user named Arthur attempts to self-update their profile doc to change their role from `analista` to `gestor`.
* **Path**: `/usuarios/arthur_uid`
* **Payload**:
```json
{
  "uid": "arthur_uid",
  "nome": "Arthur Analista",
  "email": "arthur@agro.com",
  "perfil": "gestor"
}
```

#### Payload 2: Remote Identity Spoofing (Impersonation)
* **Goal**: Operator `operator_uid` tries to submit weekly coordinates but sets `updatedBy` to `gestor_uid` to frame managers or bypass auditing.
* **Path**: `/producao/2026-W20`
* **Payload**:
```json
{
  "semana": "2026-W20",
  "cana_moida": 125000.5,
  "atr": 135.2,
  "extracao": 96.5,
  "acucar": 180000,
  "etanol": 4200,
  "updatedAt": "2026-05-20T21:38:00Z",
  "updatedBy": "gestor_uid"
}
```

#### Payload 3: Illegal Boundary Overrun - Negative Moagem
* **Goal**: Inject sub-zero ground tons to disrupt production averages.
* **Path**: `/producao/2026-W20`
* **Payload**:
```json
{
  "semana": "2026-W20",
  "cana_moida": -50.0,
  "atr": 135.2,
  "extracao": 96.5,
  "acucar": 180000,
  "etanol": 4200,
  "updatedAt": "2026-05-20T21:38:00Z",
  "updatedBy": "operator_uid"
}
```

#### Payload 4: Impossible Efficiency Extradition (> 100%)
* **Goal**: Fabricate extraction rates exceeding physical limits (e.g., 105% mill efficiency) to simulate false targets.
* **Path**: `/producao/2026-W21`
* **Payload**:
```json
{
  "semana": "2026-W21",
  "cana_moida": 140000.0,
  "atr": 130.0,
  "extracao": 105.0,
  "acucar": 200000,
  "etanol": 4500,
  "updatedAt": "2026-05-20T21:38:00Z",
  "updatedBy": "operator_uid"
}
```

#### Payload 5: Anonymous Write Interception
* **Goal**: An unauthenticated guest tries to overwrite quality metrics.
* **Path**: `/qualidade/2026-W20`
* **Payload**:
```json
{
  "semana": "2026-W20",
  "acidez_dornas": 2.5,
  "acidez_mosto": 1.1,
  "impurezas": 4.2,
  "perdas_art": 1.8,
  "updatedAt": "2026-05-20T21:38:00Z",
  "updatedBy": "anonymous"
}
```

#### Payload 6: Shadow Goal Configuration (Goals Modification by Operador)
* **Goal**: Operator attempts to lower the extraction rate goal from 96.0% to 50.0% to bypass alarms.
* **Path**: `/metas/extracao`
* **Payload**:
```json
{
  "indicador": "extracao",
  "valor_meta": 50.0,
  "tipo_comparacao": ">=",
  "unidade": "%"
}
```

#### Payload 7: Denial of Wallet (ID Poisoning Attack)
* **Goal**: Attempt to write to a highly polluted ID containing 10KB of random hex characters to exhaust Firestore lookup metrics.
* **Path**: `/producao/VERY_LONG_GARBAGE_HEX_STRING_EXCEEDING_SIZE_LIMITS_...`
* **Payload**:
```json
{
  "semana": "2026-W20",
  "cana_moida": 120000.0,
  "atr": 130.0,
  "extracao": 95.0,
  "acucar": 150000,
  "etanol": 4000,
  "updatedAt": "2026-05-20T21:38:00Z",
  "updatedBy": "operator_uid"
}
```

#### Payload 8: Immutable Field Tampering
* **Goal**: A user tries to change the identifier of the week during an update transaction.
* **Path**: `/producao/2026-W20`
* **Affected Key Change**: Changing `"semana"` to `"2026-W22"` inside document `2026-W20`.

#### Payload 9: Invalid Global Quality Metrics (Acidez Extravagante)
* **Goal**: Submit a negative fermentation acidity value to cause crashes in chemistry analysis reports.
* **Path**: `/qualidade/2026-W20`
* **Payload**:
```json
{
  "semana": "2026-W20",
  "acidez_dornas": -1.5,
  "acidez_mosto": 0.8,
  "impurezas": 3.0,
  "perdas_art": 1.5,
  "updatedAt": "2026-05-20T21:38:00Z",
  "updatedBy": "operator_uid"
}
```

#### Payload 10: Client Time Injection (Auditing Bypass)
* **Goal**: An operator attempts to log metrics indicating they were uploaded yesterday, instead of the real-time server timestamp.
* **Path**: `/producao/2026-W20`
* **Payload**:
```json
{
  "semana": "2026-W20",
  "cana_moida": 125000,
  "atr": 135,
  "extracao": 96,
  "acucar": 180000,
  "etanol": 4200,
  "updatedAt": "2020-01-01T12:00:00Z",
  "updatedBy": "operator_uid"
}
```

#### Payload 11: Analista Write Access Attempt in Custos
* **Goal**: User with standard "analista" (read-only) profile attempts to upload costs records.
* **Path**: `/custos/2026-W20`
* **Payload**:
```json
{
  "semana": "2026-W20",
  "custo_total": 4500000.0,
  "custo_por_ton": 36.0,
  "setor": "Geral",
  "custo_industrial": 2000000.0,
  "custo_agricola": 2500000.0,
  "insumos_quimicos": 350000.0,
  "updatedAt": "2026-05-20T21:38:00Z",
  "updatedBy": "analyst_uid"
}
```

#### Payload 12: Phantom Field Addition (Shadow Field Attack)
* **Goal**: Inject random extraneous data field `superUserApproved: true` into the production log.
* **Path**: `/producao/2026-W20`
* **Payload**:
```json
{
  "semana": "2026-W20",
  "cana_moida": 120000.0,
  "atr": 130.0,
  "extracao": 95.0,
  "acucar": 150000,
  "etanol": 4000,
  "updatedAt": "2026-05-20T21:38:00Z",
  "updatedBy": "operator_uid",
  "superUserApproved": true
}
```

---

### 3. Test Runner Design Blueprint

We test these scenarios against the following `firestore.rules.test.ts` structure. Built on Jest/Mocha with the `@firebase/rules-unit-testing` framework, this runner ensures absolute isolation of tests:

```typescript
import {
  initializeTestEnvironment,
  RulesTestEnvironment
} from '@firebase/rules-unit-testing';
import * as fs from 'fs';

let testEnv: RulesTestEnvironment;

describe('Agroindustrial Security Rules Verification', () => {
  beforeAll(async () => {
    testEnv = await initializeTestEnvironment({
      projectId: 'studio-9432747632-fa04b',
      firestore: {
        rules: fs.readFileSync('firestore.rules', 'utf8')
      }
    });
  });

  afterAll(async () => {
    await testEnv.cleanup();
  });

  afterEach(async () => {
    await testEnv.clearFirestore();
  });

  it('Payload 1: Prevents self-escalation of roles inside /usuarios', async () => {
    const unprivilegedDb = testEnv.authenticatedContext('arthur_uid').firestore();
    // Insert mock user as operator first using admin backend context
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().doc('usuarios/arthur_uid').set({
        uid: 'arthur_uid',
        nome: 'Arthur',
        email: 'arthur@agro.com',
        perfil: 'operador'
      });
    });

    // Attempt to update via unprivileged context to gestor
    const docRef = unprivilegedDb.doc('usuarios/arthur_uid');
    await expect(docRef.update({ perfil: 'gestor' })).rejects.toThrow();
  });

  it('Payload 2: Prevents identity spoofing in production log writes', async () => {
    const operatorDb = testEnv.authenticatedContext('operator_uid').firestore();
    const docRef = operatorDb.doc('producao/2026-W20');
    await expect(docRef.set({
      semana: '2026-W20',
      cana_moida: 125000,
      atr: 135,
      extracao: 96,
      acucar: 180000,
      etanol: 4200,
      updatedAt: new Date(),
      updatedBy: 'gestor_uid' // spoofed by operator
    })).rejects.toThrow();
  });

  // Additional payloads checks are similarly covered.
});
```
