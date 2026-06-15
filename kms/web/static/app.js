/* KMS Web UI — Vue 3 Options API */

const API_BASE = window.location.origin + '/api/v1'

const state = {
  token: localStorage.getItem('kms_token') || null,
  user: null, // { username, role }
}

/* ─── Helpers ─────────────────────────────────────────────────────────────── */

function logout() {
  state.token = null
  state.user = null
  localStorage.removeItem('kms_token')
}

async function api(method, path, body = null) {
  const headers = { 'Content-Type': 'application/json' }
  if (state.token) headers['Authorization'] = `Bearer ${state.token}`
  try {
    const res = await fetch(API_BASE + path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : null,
    })
    if (res.status === 401) { logout(); return null }
    if (res.status === 204) return {}
    if (!res.ok) {
      let err
      try { err = await res.json() } catch { err = { detail: `HTTP ${res.status}` } }
      throw new Error(err.detail || err.message || 'Erreur serveur')
    }
    return res.json()
  } catch (e) {
    if (e instanceof TypeError) throw new Error('Impossible de joindre le serveur')
    throw e
  }
}

function formatDate(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d)) return iso
  return d.toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })
}

function truncate(str, n = 12) {
  if (!str) return '—'
  return str.length > n ? str.slice(0, n) + '…' : str
}

function daysUntil(iso) {
  if (!iso) return Infinity
  const ms = new Date(iso) - new Date()
  return Math.floor(ms / 86400000)
}

function downloadCSV(rows, filename) {
  if (!rows.length) return
  const keys = Object.keys(rows[0])
  const csv = [keys.join(','), ...rows.map(r => keys.map(k => JSON.stringify(r[k] ?? '')).join(','))].join('\n')
  const a = document.createElement('a')
  a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv)
  a.download = filename
  a.click()
}

/* ─── Reusable Modal ──────────────────────────────────────────────────────── */

const AppModal = {
  name: 'AppModal',
  props: {
    title: String,
    size: { type: String, default: 'md' },
  },
  emits: ['close'],
  template: `
    <div class="modal-backdrop" @click.self="$emit('close')">
      <div class="modal" :class="'modal--' + size">
        <div class="modal__header">
          <h3 class="modal__title">{{ title }}</h3>
          <button class="modal__close" @click="$emit('close')">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
              <path d="M4.646 4.646a.5.5 0 01.708 0L8 7.293l2.646-2.647a.5.5 0 01.708.708L8.707 8l2.647 2.646a.5.5 0 01-.708.708L8 8.707l-2.646 2.647a.5.5 0 01-.708-.708L7.293 8 4.646 5.354a.5.5 0 010-.708z"/>
            </svg>
          </button>
        </div>
        <div class="modal__body">
          <slot />
        </div>
        <div class="modal__footer" v-if="$slots.footer">
          <slot name="footer" />
        </div>
      </div>
    </div>
  `,
}

/* ─── State badge ─────────────────────────────────────────────────────────── */

const StateBadge = {
  name: 'StateBadge',
  props: { state: String },
  computed: {
    cssClass() {
      const map = {
        PreActive: 'badge--gray',
        Active: 'badge--green',
        Deactivated: 'badge--warning',
        Compromised: 'badge--danger',
        Destroyed: 'badge--dark-red',
        DestroyedCompromised: 'badge--dark-red',
      }
      return map[this.state] || 'badge--gray'
    },
    label() {
      const map = {
        PreActive: 'Pré-actif',
        Active: 'Actif',
        Deactivated: 'Désactivé',
        Compromised: 'Compromis',
        Destroyed: 'Détruit',
        DestroyedCompromised: 'Détruit/Compromis',
      }
      return map[this.state] || this.state || '—'
    },
  },
  template: `<span class="badge" :class="cssClass">{{ label }}</span>`,
}

/* ─── Dashboard View ──────────────────────────────────────────────────────── */

const DashboardView = {
  name: 'DashboardView',
  components: { StateBadge },
  data() {
    return {
      loading: true,
      stats: {
        totalKeys: 0,
        activeKeys: 0,
        expiringSoon: 0,
        activeClients: 0,
      },
      recentEvents: [],
    }
  },
  async mounted() {
    await this.loadData()
  },
  methods: {
    async loadData() {
      this.loading = true
      try {
        const [keysRes, clientsRes, auditRes] = await Promise.allSettled([
          api('GET', '/keys/?max_items=1000'),
          api('GET', '/clients/?max_items=1000'),
          api('GET', '/audit/?limit=5'),
        ])

        if (keysRes.status === 'fulfilled' && keysRes.value) {
          const keys = keysRes.value.items || keysRes.value || []
          this.stats.totalKeys = keysRes.value.total || keys.length
          this.stats.activeKeys = keys.filter(k => k.state === 'Active').length
          this.stats.expiringSoon = keys.filter(k => {
            const d = daysUntil(k.deactivation_date)
            return d >= 0 && d <= 30
          }).length
        }
        if (clientsRes.status === 'fulfilled' && clientsRes.value) {
          const clients = clientsRes.value.items || clientsRes.value || []
          this.stats.activeClients = clients.filter(c => c.is_active !== false).length
        }
        if (auditRes.status === 'fulfilled' && auditRes.value) {
          this.recentEvents = auditRes.value.items || auditRes.value || []
        }
      } finally {
        this.loading = false
      }
    },
    resultClass(result) {
      if (!result) return 'badge--gray'
      const r = result.toLowerCase()
      if (r === 'success') return 'badge--green'
      if (r.includes('fail') || r === 'operationfailed') return 'badge--danger'
      return 'badge--gray'
    },
    resultLabel(result) {
      if (!result) return '—'
      if (result === 'Success') return 'Succès'
      if (result === 'OperationFailed') return 'Échec'
      return result
    },
    formatDate,
  },
  template: `
    <div class="view-dashboard">
      <div v-if="loading" class="loading-center"><div class="spinner"></div></div>
      <template v-else>
        <div class="stat-cards">
          <div class="stat-card stat-card--blue">
            <div class="stat-card__icon">
              <svg width="24" height="24" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a2 2 0 012 2v4H6V3a2 2 0 012-2zm3 6V3a3 3 0 00-6 0v4a2 2 0 00-2 2v5a2 2 0 002 2h6a2 2 0 002-2V9a2 2 0 00-2-2z"/></svg>
            </div>
            <div class="stat-card__body">
              <div class="stat-card__value">{{ stats.totalKeys }}</div>
              <div class="stat-card__label">Total des clés</div>
            </div>
          </div>
          <div class="stat-card stat-card--green">
            <div class="stat-card__icon">
              <svg width="24" height="24" viewBox="0 0 16 16" fill="currentColor"><path d="M13.78 4.22a.75.75 0 010 1.06l-7.25 7.25a.75.75 0 01-1.06 0L2.22 9.28a.75.75 0 011.06-1.06L6 10.94l6.72-6.72a.75.75 0 011.06 0z"/></svg>
            </div>
            <div class="stat-card__body">
              <div class="stat-card__value">{{ stats.activeKeys }}</div>
              <div class="stat-card__label">Clés actives</div>
            </div>
          </div>
          <div class="stat-card stat-card--warning">
            <div class="stat-card__icon">
              <svg width="24" height="24" viewBox="0 0 16 16" fill="currentColor"><path d="M8.982 1.566a1.13 1.13 0 00-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 01-1.1 0L7.1 5.995A.905.905 0 018 5zm.002 6a1 1 0 110 2 1 1 0 010-2z"/></svg>
            </div>
            <div class="stat-card__body">
              <div class="stat-card__value">{{ stats.expiringSoon }}</div>
              <div class="stat-card__label">Expirent bientôt</div>
            </div>
          </div>
          <div class="stat-card stat-card--purple">
            <div class="stat-card__icon">
              <svg width="24" height="24" viewBox="0 0 16 16" fill="currentColor"><path d="M0 4a2 2 0 012-2h12a2 2 0 012 2v1H0V4zm0 3h16v5a2 2 0 01-2 2H2a2 2 0 01-2-2V7z"/></svg>
            </div>
            <div class="stat-card__body">
              <div class="stat-card__value">{{ stats.activeClients }}</div>
              <div class="stat-card__label">Clients actifs</div>
            </div>
          </div>
        </div>

        <div class="card mt-4">
          <div class="card__header">
            <h2 class="card__title">Activité récente</h2>
          </div>
          <div class="table-wrapper">
            <table class="table">
              <thead>
                <tr>
                  <th>Horodatage</th>
                  <th>Acteur</th>
                  <th>Opération</th>
                  <th>Objet</th>
                  <th>Résultat</th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="!recentEvents.length">
                  <td colspan="5" class="table__empty">Aucun événement récent</td>
                </tr>
                <tr v-for="ev in recentEvents" :key="ev.id">
                  <td class="text-mono text-sm">{{ formatDate(ev.timestamp) }}</td>
                  <td>{{ ev.actor || ev.username || '—' }}</td>
                  <td>{{ ev.operation || '—' }}</td>
                  <td class="text-mono text-sm">{{ truncate(ev.object_id) }}</td>
                  <td><span class="badge" :class="resultClass(ev.result)">{{ resultLabel(ev.result) }}</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </template>
    </div>
  `,
}

/* ─── Objects View ────────────────────────────────────────────────────────── */

const ObjectsView = {
  name: 'ObjectsView',
  components: { AppModal, StateBadge },
  inject: ['showToast', 'showConfirm'],
  data() {
    return {
      loading: false,
      items: [],
      total: 0,
      page: 1,
      perPage: 20,
      filters: { algorithm: '', state: '', search: '' },

      selectedItem: null,
      showDetail: false,

      showNewSymKey: false,
      showNewKeyPair: false,

      newSymKey: { name: '', algorithm: 'AES', length: 256, cryptographic_usage_mask: 12 },
      newKeyPair: { name: '', algorithm: 'RSA', length: 2048 },
      formLoading: false,

      algorithms: ['AES', 'RSA', 'EC', 'Ed25519', 'ChaCha20'],
      states: [
        { value: '', label: 'Tous les états' },
        { value: 'PreActive', label: 'Pré-actif' },
        { value: 'Active', label: 'Actif' },
        { value: 'Deactivated', label: 'Désactivé' },
        { value: 'Compromised', label: 'Compromis' },
        { value: 'Destroyed', label: 'Détruit' },
      ],
    }
  },
  computed: {
    rsaLengths() { return [1024, 2048, 3072, 4096] },
    aesLengths() { return [128, 192, 256] },
    symKeyLengths() {
      if (this.newSymKey.algorithm === 'AES') return [128, 192, 256]
      if (this.newSymKey.algorithm === 'ChaCha20') return [256]
      return [128, 192, 256]
    },
    offset() { return (this.page - 1) * this.perPage },
    totalPages() { return Math.max(1, Math.ceil(this.total / this.perPage)) },
  },
  async mounted() {
    await this.loadItems()
  },
  methods: {
    async loadItems() {
      this.loading = true
      try {
        const params = new URLSearchParams()
        params.set('skip', this.offset)
        params.set('limit', this.perPage)
        if (this.filters.algorithm) params.set('algorithm', this.filters.algorithm)
        if (this.filters.state) params.set('state', this.filters.state)
        if (this.filters.search) params.set('name', this.filters.search)

        const res = await api('GET', '/keys/?' + params)
        if (res) {
          this.items = res.items || res || []
          this.total = res.total || this.items.length
        }
      } catch (e) {
        this.showToast(e.message, 'error')
      } finally {
        this.loading = false
      }
    },
    async applyFilters() {
      this.page = 1
      await this.loadItems()
    },
    async prevPage() { if (this.page > 1) { this.page--; await this.loadItems() } },
    async nextPage() { if (this.page < this.totalPages) { this.page++; await this.loadItems() } },

    openDetail(item) {
      this.selectedItem = item
      this.showDetail = true
    },

    async activate(item) {
      try {
        await api('POST', `/keys/${item.unique_identifier}/activate`)
        this.showToast('Clé activée avec succès', 'success')
        await this.loadItems()
      } catch (e) { this.showToast(e.message, 'error') }
    },

    async revoke(item) {
      const ok = await this.showConfirm(
        'Révoquer la clé',
        `Voulez-vous révoquer la clé « ${item.unique_identifier} » ? Cette action est irréversible.`
      )
      if (!ok) return
      try {
        await api('POST', `/keys/${item.unique_identifier}/revoke`, { revocation_reason: 'KeyCompromise' })
        this.showToast('Clé révoquée', 'success')
        await this.loadItems()
      } catch (e) { this.showToast(e.message, 'error') }
    },

    async destroy(item) {
      const ok = await this.showConfirm(
        'Détruire la clé',
        `Voulez-vous DÉTRUIRE définitivement la clé « ${item.unique_identifier} » ? Cette action est IRRÉVERSIBLE.`
      )
      if (!ok) return
      try {
        await api('DELETE', `/keys/${item.unique_identifier}`)
        this.showToast('Clé détruite', 'success')
        await this.loadItems()
      } catch (e) { this.showToast(e.message, 'error') }
    },

    async createSymKey() {
      this.formLoading = true
      try {
        await api('POST', '/keys/', {
          object_type: 'SymmetricKey',
          ...this.newSymKey,
        })
        this.showToast('Clé symétrique créée', 'success')
        this.showNewSymKey = false
        this.newSymKey = { name: '', algorithm: 'AES', length: 256, cryptographic_usage_mask: 12 }
        await this.loadItems()
      } catch (e) { this.showToast(e.message, 'error') }
      finally { this.formLoading = false }
    },

    async createKeyPair() {
      this.formLoading = true
      try {
        await api('POST', '/keys/pair', { ...this.newKeyPair })
        this.showToast('Paire de clés créée', 'success')
        this.showNewKeyPair = false
        this.newKeyPair = { name: '', algorithm: 'RSA', length: 2048 }
        await this.loadItems()
      } catch (e) { this.showToast(e.message, 'error') }
      finally { this.formLoading = false }
    },

    canActivate(item) { return item.state === 'PreActive' },
    canRevoke(item) { return ['Active', 'PreActive'].includes(item.state) },
    canDestroy(item) { return ['Deactivated', 'Compromised'].includes(item.state) },

    formatDate,
    truncate,
  },
  template: `
    <div class="view-objects">
      <!-- Toolbar -->
      <div class="toolbar">
        <div class="toolbar__filters">
          <select class="form-select" v-model="filters.algorithm" @change="applyFilters">
            <option value="">Tous les algorithmes</option>
            <option v-for="a in algorithms" :key="a" :value="a">{{ a }}</option>
          </select>
          <select class="form-select" v-model="filters.state" @change="applyFilters">
            <option v-for="s in states" :key="s.value" :value="s.value">{{ s.label }}</option>
          </select>
          <input
            class="form-input"
            type="search"
            v-model="filters.search"
            placeholder="Rechercher par nom…"
            @keyup.enter="applyFilters"
          />
          <button class="btn btn--secondary" @click="applyFilters">Filtrer</button>
        </div>
        <div class="toolbar__actions">
          <button class="btn btn--primary" @click="showNewSymKey = true">
            + Clé symétrique
          </button>
          <button class="btn btn--secondary" @click="showNewKeyPair = true">
            + Paire de clés
          </button>
        </div>
      </div>

      <!-- Table -->
      <div class="card">
        <div v-if="loading" class="loading-center"><div class="spinner"></div></div>
        <div v-else class="table-wrapper">
          <table class="table table--hoverable">
            <thead>
              <tr>
                <th>Identifiant</th>
                <th>Type</th>
                <th>Algorithme</th>
                <th>Longueur</th>
                <th>État</th>
                <th>Noms</th>
                <th>Créé le</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="!items.length">
                <td colspan="8" class="table__empty">Aucun objet cryptographique trouvé</td>
              </tr>
              <tr
                v-for="item in items"
                :key="item.unique_identifier"
                @click="openDetail(item)"
                class="table__row--clickable"
              >
                <td class="text-mono text-sm" :title="item.unique_identifier">{{ truncate(item.unique_identifier, 16) }}</td>
                <td>{{ item.object_type || '—' }}</td>
                <td>{{ item.algorithm || item.cryptographic_algorithm || '—' }}</td>
                <td>{{ item.length || item.cryptographic_length || '—' }}</td>
                <td><state-badge :state="item.state" /></td>
                <td class="text-sm">{{ (item.names || []).join(', ') || '—' }}</td>
                <td class="text-sm">{{ formatDate(item.created_date || item.initial_date) }}</td>
                <td @click.stop>
                  <div class="btn-group">
                    <button
                      v-if="canActivate(item)"
                      class="btn btn--sm btn--primary"
                      @click.stop="activate(item)"
                      title="Activer"
                    >Activer</button>
                    <button
                      v-if="canRevoke(item)"
                      class="btn btn--sm btn--warning"
                      @click.stop="revoke(item)"
                      title="Révoquer"
                    >Révoquer</button>
                    <button
                      v-if="canDestroy(item)"
                      class="btn btn--sm btn--danger"
                      @click.stop="destroy(item)"
                      title="Détruire"
                    >Détruire</button>
                    <button class="btn btn--sm btn--secondary" @click.stop="openDetail(item)">Détails</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <!-- Pagination -->
        <div class="pagination" v-if="!loading">
          <span class="pagination__info">{{ total }} objet(s) — Page {{ page }} / {{ totalPages }}</span>
          <div class="pagination__controls">
            <button class="btn btn--sm btn--secondary" :disabled="page <= 1" @click="prevPage">← Précédent</button>
            <button class="btn btn--sm btn--secondary" :disabled="page >= totalPages" @click="nextPage">Suivant →</button>
          </div>
        </div>
      </div>

      <!-- Detail modal -->
      <app-modal v-if="showDetail && selectedItem" :title="'Détails — ' + truncate(selectedItem.unique_identifier, 20)" size="lg" @close="showDetail = false">
        <div class="detail-grid">
          <div class="detail-row">
            <span class="detail-label">Identifiant</span>
            <span class="detail-value text-mono">{{ selectedItem.unique_identifier }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Type</span>
            <span class="detail-value">{{ selectedItem.object_type || '—' }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Algorithme</span>
            <span class="detail-value">{{ selectedItem.algorithm || selectedItem.cryptographic_algorithm || '—' }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Longueur</span>
            <span class="detail-value">{{ selectedItem.length || selectedItem.cryptographic_length || '—' }} bits</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">État</span>
            <state-badge :state="selectedItem.state" />
          </div>
          <div class="detail-row">
            <span class="detail-label">Noms</span>
            <span class="detail-value">{{ (selectedItem.names || []).join(', ') || '—' }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Créé le</span>
            <span class="detail-value">{{ formatDate(selectedItem.created_date || selectedItem.initial_date) }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Activation</span>
            <span class="detail-value">{{ formatDate(selectedItem.activation_date) }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Désactivation</span>
            <span class="detail-value">{{ formatDate(selectedItem.deactivation_date) }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Destruction</span>
            <span class="detail-value">{{ formatDate(selectedItem.destroy_date) }}</span>
          </div>
          <div class="detail-row" v-if="selectedItem.links && selectedItem.links.length">
            <span class="detail-label">Liens</span>
            <div class="detail-value">
              <div v-for="link in selectedItem.links" :key="link.linked_object_identifier" class="text-sm">
                {{ link.link_type }}: <span class="text-mono">{{ link.linked_object_identifier }}</span>
              </div>
            </div>
          </div>
          <div class="detail-row" v-if="selectedItem.object_group">
            <span class="detail-label">Groupe</span>
            <span class="detail-value">{{ selectedItem.object_group }}</span>
          </div>
          <div class="detail-row" v-if="selectedItem.sensitive !== undefined">
            <span class="detail-label">Sensible</span>
            <span class="detail-value">{{ selectedItem.sensitive ? 'Oui' : 'Non' }}</span>
          </div>
        </div>
        <template #footer>
          <button class="btn btn--secondary" @click="showDetail = false">Fermer</button>
        </template>
      </app-modal>

      <!-- New symmetric key modal -->
      <app-modal v-if="showNewSymKey" title="Nouvelle clé symétrique" @close="showNewSymKey = false">
        <form @submit.prevent="createSymKey">
          <div class="form-group">
            <label class="form-label">Nom <span class="text-secondary">(optionnel)</span></label>
            <input class="form-input" v-model="newSymKey.name" placeholder="ma-cle-aes" />
          </div>
          <div class="form-group">
            <label class="form-label">Algorithme</label>
            <select class="form-select" v-model="newSymKey.algorithm">
              <option value="AES">AES</option>
              <option value="ChaCha20">ChaCha20</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Longueur (bits)</label>
            <select class="form-select" v-model.number="newSymKey.length">
              <option v-for="l in symKeyLengths" :key="l" :value="l">{{ l }}</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Usage cryptographique</label>
            <select class="form-select" v-model.number="newSymKey.cryptographic_usage_mask">
              <option :value="4">Chiffrement</option>
              <option :value="8">Déchiffrement</option>
              <option :value="12">Chiffrement + Déchiffrement</option>
            </select>
          </div>
        </form>
        <template #footer>
          <button class="btn btn--secondary" @click="showNewSymKey = false">Annuler</button>
          <button class="btn btn--primary" @click="createSymKey" :disabled="formLoading">
            <span v-if="formLoading" class="spinner spinner--sm"></span>
            <span v-else>Créer</span>
          </button>
        </template>
      </app-modal>

      <!-- New key pair modal -->
      <app-modal v-if="showNewKeyPair" title="Nouvelle paire de clés" @close="showNewKeyPair = false">
        <form @submit.prevent="createKeyPair">
          <div class="form-group">
            <label class="form-label">Nom <span class="text-secondary">(optionnel)</span></label>
            <input class="form-input" v-model="newKeyPair.name" placeholder="ma-paire-rsa" />
          </div>
          <div class="form-group">
            <label class="form-label">Algorithme</label>
            <select class="form-select" v-model="newKeyPair.algorithm">
              <option value="RSA">RSA</option>
              <option value="EC">EC (Elliptic Curve)</option>
              <option value="Ed25519">Ed25519</option>
            </select>
          </div>
          <div class="form-group" v-if="newKeyPair.algorithm === 'RSA'">
            <label class="form-label">Longueur (bits)</label>
            <select class="form-select" v-model.number="newKeyPair.length">
              <option v-for="l in rsaLengths" :key="l" :value="l">{{ l }}</option>
            </select>
          </div>
          <div class="form-group" v-if="newKeyPair.algorithm === 'EC'">
            <label class="form-label">Courbe</label>
            <select class="form-select" v-model="newKeyPair.curve">
              <option value="P-256">P-256 (secp256r1)</option>
              <option value="P-384">P-384 (secp384r1)</option>
              <option value="P-521">P-521 (secp521r1)</option>
            </select>
          </div>
        </form>
        <template #footer>
          <button class="btn btn--secondary" @click="showNewKeyPair = false">Annuler</button>
          <button class="btn btn--primary" @click="createKeyPair" :disabled="formLoading">
            <span v-if="formLoading" class="spinner spinner--sm"></span>
            <span v-else>Créer</span>
          </button>
        </template>
      </app-modal>
    </div>
  `,
}

/* ─── Clients View ────────────────────────────────────────────────────────── */

const ClientsView = {
  name: 'ClientsView',
  components: { AppModal },
  inject: ['showToast', 'showConfirm'],
  data() {
    return {
      loading: false,
      items: [],
      total: 0,
      page: 1,
      perPage: 20,
      showEnroll: false,
      selectedClient: null,
      showDetail: false,
      formLoading: false,
      newClient: {
        name: '',
        client_type: 'KMIP',
        object_group: '',
        policy_name: '',
      },
    }
  },
  computed: {
    offset() { return (this.page - 1) * this.perPage },
    totalPages() { return Math.max(1, Math.ceil(this.total / this.perPage)) },
  },
  async mounted() { await this.loadItems() },
  methods: {
    async loadItems() {
      this.loading = true
      try {
        const params = new URLSearchParams({ skip: this.offset, limit: this.perPage })
        const res = await api('GET', '/clients/?' + params)
        if (res) {
          this.items = res.items || res || []
          this.total = res.total || this.items.length
        }
      } catch (e) { this.showToast(e.message, 'error') }
      finally { this.loading = false }
    },
    async prevPage() { if (this.page > 1) { this.page--; await this.loadItems() } },
    async nextPage() { if (this.page < this.totalPages) { this.page++; await this.loadItems() } },
    async enroll() {
      this.formLoading = true
      try {
        await api('POST', '/clients/', this.newClient)
        this.showToast('Client enrôlé avec succès', 'success')
        this.showEnroll = false
        this.newClient = { name: '', client_type: 'KMIP', object_group: '', policy_name: '' }
        await this.loadItems()
      } catch (e) { this.showToast(e.message, 'error') }
      finally { this.formLoading = false }
    },
    async deactivate(client) {
      const ok = await this.showConfirm(
        'Désactiver le client',
        `Voulez-vous désactiver le client « ${client.name} » ?`
      )
      if (!ok) return
      try {
        await api('PATCH', `/clients/${client.id}`, { is_active: false })
        this.showToast('Client désactivé', 'success')
        await this.loadItems()
      } catch (e) { this.showToast(e.message, 'error') }
    },
    openDetail(client) { this.selectedClient = client; this.showDetail = true },
    formatDate,
  },
  template: `
    <div class="view-clients">
      <div class="toolbar">
        <div class="toolbar__filters"></div>
        <div class="toolbar__actions">
          <button class="btn btn--primary" @click="showEnroll = true">+ Enrôler un client</button>
        </div>
      </div>

      <div class="card">
        <div v-if="loading" class="loading-center"><div class="spinner"></div></div>
        <div v-else class="table-wrapper">
          <table class="table table--hoverable">
            <thead>
              <tr>
                <th>Nom</th>
                <th>Type</th>
                <th>Groupe</th>
                <th>Politique</th>
                <th>Statut</th>
                <th>Dernière activité</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="!items.length">
                <td colspan="7" class="table__empty">Aucun client KMIP enrôlé</td>
              </tr>
              <tr v-for="client in items" :key="client.id" class="table__row--clickable" @click="openDetail(client)">
                <td>{{ client.name || '—' }}</td>
                <td>{{ client.client_type || client.type || 'KMIP' }}</td>
                <td>{{ client.object_group || '—' }}</td>
                <td>{{ client.policy_name || client.policy || '—' }}</td>
                <td>
                  <span class="badge" :class="client.is_active !== false ? 'badge--green' : 'badge--gray'">
                    {{ client.is_active !== false ? 'Actif' : 'Inactif' }}
                  </span>
                </td>
                <td class="text-sm">{{ formatDate(client.last_seen || client.updated_at) }}</td>
                <td @click.stop>
                  <div class="btn-group">
                    <button class="btn btn--sm btn--secondary" @click.stop="openDetail(client)">Voir</button>
                    <button
                      v-if="client.is_active !== false"
                      class="btn btn--sm btn--warning"
                      @click.stop="deactivate(client)"
                    >Désactiver</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="pagination" v-if="!loading">
          <span class="pagination__info">{{ total }} client(s) — Page {{ page }} / {{ totalPages }}</span>
          <div class="pagination__controls">
            <button class="btn btn--sm btn--secondary" :disabled="page <= 1" @click="prevPage">← Précédent</button>
            <button class="btn btn--sm btn--secondary" :disabled="page >= totalPages" @click="nextPage">Suivant →</button>
          </div>
        </div>
      </div>

      <!-- Detail modal -->
      <app-modal v-if="showDetail && selectedClient" :title="'Client — ' + selectedClient.name" size="lg" @close="showDetail = false">
        <div class="detail-grid">
          <div class="detail-row"><span class="detail-label">ID</span><span class="detail-value text-mono">{{ selectedClient.id }}</span></div>
          <div class="detail-row"><span class="detail-label">Nom</span><span class="detail-value">{{ selectedClient.name }}</span></div>
          <div class="detail-row"><span class="detail-label">Type</span><span class="detail-value">{{ selectedClient.client_type || 'KMIP' }}</span></div>
          <div class="detail-row"><span class="detail-label">Groupe</span><span class="detail-value">{{ selectedClient.object_group || '—' }}</span></div>
          <div class="detail-row"><span class="detail-label">Politique</span><span class="detail-value">{{ selectedClient.policy_name || '—' }}</span></div>
          <div class="detail-row"><span class="detail-label">Certificat</span><span class="detail-value text-mono text-sm">{{ selectedClient.certificate_subject || selectedClient.cn || '—' }}</span></div>
          <div class="detail-row"><span class="detail-label">Statut</span><span class="badge" :class="selectedClient.is_active !== false ? 'badge--green' : 'badge--gray'">{{ selectedClient.is_active !== false ? 'Actif' : 'Inactif' }}</span></div>
          <div class="detail-row"><span class="detail-label">Créé le</span><span class="detail-value">{{ formatDate(selectedClient.created_at) }}</span></div>
          <div class="detail-row"><span class="detail-label">Dernière activité</span><span class="detail-value">{{ formatDate(selectedClient.last_seen || selectedClient.updated_at) }}</span></div>
        </div>
        <template #footer>
          <button class="btn btn--secondary" @click="showDetail = false">Fermer</button>
        </template>
      </app-modal>

      <!-- Enroll modal -->
      <app-modal v-if="showEnroll" title="Enrôler un client KMIP" @close="showEnroll = false">
        <form @submit.prevent="enroll">
          <div class="form-group">
            <label class="form-label">Nom du client <span class="required">*</span></label>
            <input class="form-input" v-model="newClient.name" placeholder="client-erp-prod" required />
          </div>
          <div class="form-group">
            <label class="form-label">Type</label>
            <select class="form-select" v-model="newClient.client_type">
              <option value="KMIP">KMIP</option>
              <option value="REST">REST</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Groupe d'objets</label>
            <input class="form-input" v-model="newClient.object_group" placeholder="groupe-production" />
          </div>
          <div class="form-group">
            <label class="form-label">Politique d'accès</label>
            <input class="form-input" v-model="newClient.policy_name" placeholder="default" />
          </div>
        </form>
        <template #footer>
          <button class="btn btn--secondary" @click="showEnroll = false">Annuler</button>
          <button class="btn btn--primary" @click="enroll" :disabled="formLoading">
            <span v-if="formLoading" class="spinner spinner--sm"></span>
            <span v-else>Enrôler</span>
          </button>
        </template>
      </app-modal>
    </div>
  `,
}

/* ─── Audit View ──────────────────────────────────────────────────────────── */

const AuditView = {
  name: 'AuditView',
  inject: ['showToast'],
  data() {
    return {
      loading: false,
      items: [],
      total: 0,
      page: 1,
      perPage: 20,
      filters: {
        actor: '',
        operation: '',
        result: '',
        date_from: '',
        date_to: '',
      },
    }
  },
  computed: {
    offset() { return (this.page - 1) * this.perPage },
    totalPages() { return Math.max(1, Math.ceil(this.total / this.perPage)) },
  },
  async mounted() { await this.loadItems() },
  methods: {
    async loadItems() {
      this.loading = true
      try {
        const params = new URLSearchParams({ skip: this.offset, limit: this.perPage })
        if (this.filters.actor) params.set('actor', this.filters.actor)
        if (this.filters.operation) params.set('operation', this.filters.operation)
        if (this.filters.result) params.set('result', this.filters.result)
        if (this.filters.date_from) params.set('date_from', this.filters.date_from)
        if (this.filters.date_to) params.set('date_to', this.filters.date_to)
        const res = await api('GET', '/audit/?' + params)
        if (res) {
          this.items = res.items || res || []
          this.total = res.total || this.items.length
        }
      } catch (e) { this.showToast(e.message, 'error') }
      finally { this.loading = false }
    },
    async applyFilters() { this.page = 1; await this.loadItems() },
    async prevPage() { if (this.page > 1) { this.page--; await this.loadItems() } },
    async nextPage() { if (this.page < this.totalPages) { this.page++; await this.loadItems() } },
    resultClass(result) {
      if (!result) return 'badge--gray'
      if (result === 'Success') return 'badge--green'
      if (result === 'OperationFailed') return 'badge--danger'
      return 'badge--gray'
    },
    resultLabel(result) {
      if (!result) return '—'
      if (result === 'Success') return 'Succès'
      if (result === 'OperationFailed') return 'Échec'
      return result
    },
    exportCSV() {
      const rows = this.items.map(e => ({
        Horodatage: e.timestamp,
        Acteur: e.actor || e.username || '',
        Protocole: e.protocol || '',
        Opération: e.operation || '',
        'Identifiant objet': e.object_id || '',
        Résultat: e.result || '',
        Détails: JSON.stringify(e.details || {}),
      }))
      downloadCSV(rows, `audit-${new Date().toISOString().slice(0, 10)}.csv`)
    },
    formatDate,
    truncate,
  },
  template: `
    <div class="view-audit">
      <div class="toolbar toolbar--wrap">
        <div class="toolbar__filters">
          <input class="form-input" v-model="filters.actor" placeholder="Acteur…" @keyup.enter="applyFilters" />
          <input class="form-input" v-model="filters.operation" placeholder="Opération…" @keyup.enter="applyFilters" />
          <select class="form-select" v-model="filters.result" @change="applyFilters">
            <option value="">Tous les résultats</option>
            <option value="Success">Succès</option>
            <option value="OperationFailed">Échec</option>
          </select>
          <input class="form-input" type="date" v-model="filters.date_from" @change="applyFilters" title="Date début" />
          <input class="form-input" type="date" v-model="filters.date_to" @change="applyFilters" title="Date fin" />
          <button class="btn btn--secondary" @click="applyFilters">Filtrer</button>
        </div>
        <div class="toolbar__actions">
          <button class="btn btn--secondary" @click="exportCSV">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M.5 9.9a.5.5 0 01.5.5v2.5a1 1 0 001 1h12a1 1 0 001-1v-2.5a.5.5 0 011 0v2.5a2 2 0 01-2 2H2a2 2 0 01-2-2v-2.5a.5.5 0 01.5-.5z"/><path d="M7.646 11.854a.5.5 0 00.708 0l3-3a.5.5 0 00-.708-.708L8.5 10.293V1.5a.5.5 0 00-1 0v8.793L5.354 8.146a.5.5 0 10-.708.708l3 3z"/></svg>
            Exporter CSV
          </button>
        </div>
      </div>

      <div class="card">
        <div v-if="loading" class="loading-center"><div class="spinner"></div></div>
        <div v-else class="table-wrapper">
          <table class="table">
            <thead>
              <tr>
                <th>Horodatage</th>
                <th>Acteur</th>
                <th>Protocole</th>
                <th>Opération</th>
                <th>Identifiant objet</th>
                <th>Résultat</th>
                <th>Détails</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="!items.length">
                <td colspan="7" class="table__empty">Aucun événement d'audit trouvé</td>
              </tr>
              <tr v-for="ev in items" :key="ev.id">
                <td class="text-mono text-sm" style="white-space:nowrap">{{ formatDate(ev.timestamp) }}</td>
                <td>{{ ev.actor || ev.username || '—' }}</td>
                <td><span class="badge badge--gray">{{ ev.protocol || 'REST' }}</span></td>
                <td>{{ ev.operation || '—' }}</td>
                <td class="text-mono text-sm" :title="ev.object_id">{{ truncate(ev.object_id, 14) }}</td>
                <td><span class="badge" :class="resultClass(ev.result)">{{ resultLabel(ev.result) }}</span></td>
                <td class="text-sm text-secondary">{{ ev.details ? JSON.stringify(ev.details).slice(0, 60) : '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="pagination" v-if="!loading">
          <span class="pagination__info">{{ total }} événement(s) — Page {{ page }} / {{ totalPages }}</span>
          <div class="pagination__controls">
            <button class="btn btn--sm btn--secondary" :disabled="page <= 1" @click="prevPage">← Précédent</button>
            <button class="btn btn--sm btn--secondary" :disabled="page >= totalPages" @click="nextPage">Suivant →</button>
          </div>
        </div>
      </div>
    </div>
  `,
}

/* ─── Admin View ──────────────────────────────────────────────────────────── */

const AdminView = {
  name: 'AdminView',
  components: { AppModal },
  inject: ['showToast', 'showConfirm'],
  data() {
    return {
      activeTab: 'users',
      users: [],
      usersLoading: false,
      hsmStatus: null,
      hsmLoading: false,
      health: null,
      healthLoading: false,
      showCreateUser: false,
      formLoading: false,
      newUser: { username: '', password: '', role: 'operator' },
      roles: [
        { value: 'operator', label: 'Opérateur' },
        { value: 'auditor', label: 'Auditeur' },
        { value: 'sec_admin', label: 'Administrateur sécurité' },
        { value: 'sys_admin', label: 'Administrateur système' },
      ],
    }
  },
  async mounted() { await this.loadUsers() },
  methods: {
    async setTab(tab) {
      this.activeTab = tab
      if (tab === 'users' && !this.users.length) await this.loadUsers()
      if (tab === 'hsm' && !this.hsmStatus) await this.loadHsm()
      if (tab === 'health' && !this.health) await this.loadHealth()
    },
    async loadUsers() {
      this.usersLoading = true
      try {
        const res = await api('GET', '/admin/users/')
        if (res) this.users = res.items || res || []
      } catch (e) { this.showToast(e.message, 'error') }
      finally { this.usersLoading = false }
    },
    async loadHsm() {
      this.hsmLoading = true
      try {
        this.hsmStatus = await api('GET', '/admin/hsm/status')
      } catch (e) { this.showToast(e.message, 'error') }
      finally { this.hsmLoading = false }
    },
    async loadHealth() {
      this.healthLoading = true
      try {
        this.health = await api('GET', '/admin/health')
      } catch (e) { this.showToast(e.message, 'error') }
      finally { this.healthLoading = false }
    },
    async createUser() {
      this.formLoading = true
      try {
        await api('POST', '/admin/users/', this.newUser)
        this.showToast('Utilisateur créé', 'success')
        this.showCreateUser = false
        this.newUser = { username: '', password: '', role: 'operator' }
        await this.loadUsers()
      } catch (e) { this.showToast(e.message, 'error') }
      finally { this.formLoading = false }
    },
    async deleteUser(user) {
      const ok = await this.showConfirm('Supprimer l\'utilisateur', `Supprimer « ${user.username} » ?`)
      if (!ok) return
      try {
        await api('DELETE', `/admin/users/${user.id}`)
        this.showToast('Utilisateur supprimé', 'success')
        await this.loadUsers()
      } catch (e) { this.showToast(e.message, 'error') }
    },
    roleLabel(role) {
      const map = { operator: 'Opérateur', auditor: 'Auditeur', sec_admin: 'Admin sécurité', sys_admin: 'Admin système' }
      return map[role] || role
    },
    roleClass(role) {
      const map = { operator: 'badge--gray', auditor: 'badge--blue', sec_admin: 'badge--warning', sys_admin: 'badge--danger' }
      return map[role] || 'badge--gray'
    },
    healthClass(status) {
      if (!status) return 'badge--gray'
      const s = String(status).toLowerCase()
      if (s === 'ok' || s === 'healthy' || s === 'up') return 'badge--green'
      if (s === 'degraded' || s === 'warning') return 'badge--warning'
      return 'badge--danger'
    },
    formatDate,
  },
  template: `
    <div class="view-admin">
      <div class="tabs">
        <button class="tab" :class="{ 'tab--active': activeTab === 'users' }" @click="setTab('users')">Utilisateurs</button>
        <button class="tab" :class="{ 'tab--active': activeTab === 'hsm' }" @click="setTab('hsm')">HSM</button>
        <button class="tab" :class="{ 'tab--active': activeTab === 'health' }" @click="setTab('health')">Santé système</button>
      </div>

      <!-- Users tab -->
      <div v-if="activeTab === 'users'" class="tab-content">
        <div class="toolbar">
          <div class="toolbar__filters"></div>
          <div class="toolbar__actions">
            <button class="btn btn--primary" @click="showCreateUser = true">+ Nouvel utilisateur</button>
          </div>
        </div>
        <div class="card">
          <div v-if="usersLoading" class="loading-center"><div class="spinner"></div></div>
          <div v-else class="table-wrapper">
            <table class="table">
              <thead>
                <tr>
                  <th>Identifiant</th>
                  <th>Nom d'utilisateur</th>
                  <th>Rôle</th>
                  <th>Créé le</th>
                  <th>Dernière connexion</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="!users.length">
                  <td colspan="6" class="table__empty">Aucun utilisateur</td>
                </tr>
                <tr v-for="user in users" :key="user.id">
                  <td class="text-mono text-sm">{{ user.id }}</td>
                  <td>{{ user.username }}</td>
                  <td><span class="badge" :class="roleClass(user.role)">{{ roleLabel(user.role) }}</span></td>
                  <td class="text-sm">{{ formatDate(user.created_at) }}</td>
                  <td class="text-sm">{{ formatDate(user.last_login) }}</td>
                  <td>
                    <button class="btn btn--sm btn--danger" @click="deleteUser(user)">Supprimer</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- HSM tab -->
      <div v-if="activeTab === 'hsm'" class="tab-content">
        <div class="card">
          <div v-if="hsmLoading" class="loading-center"><div class="spinner"></div></div>
          <div v-else-if="!hsmStatus" class="table__empty">Impossible de récupérer le statut HSM</div>
          <div v-else class="detail-grid">
            <div v-for="(value, key) in hsmStatus" :key="key" class="detail-row">
              <span class="detail-label">{{ key }}</span>
              <span class="detail-value">
                <span v-if="['status','state','health'].includes(key.toLowerCase())" class="badge" :class="healthClass(value)">{{ value }}</span>
                <span v-else>{{ value }}</span>
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Health tab -->
      <div v-if="activeTab === 'health'" class="tab-content">
        <div class="card">
          <div v-if="healthLoading" class="loading-center"><div class="spinner"></div></div>
          <div v-else-if="!health" class="table__empty">Impossible de récupérer la santé du système</div>
          <div v-else>
            <div class="detail-grid">
              <div v-for="(value, key) in health" :key="key" class="detail-row">
                <span class="detail-label">{{ key }}</span>
                <span class="detail-value">
                  <span v-if="typeof value === 'object' && value !== null">
                    <span v-for="(v2, k2) in value" :key="k2" class="badge" :class="healthClass(v2)" style="margin-right:4px">{{ k2 }}: {{ v2 }}</span>
                  </span>
                  <span v-else-if="['status','state','health'].includes(key.toLowerCase())" class="badge" :class="healthClass(value)">{{ value }}</span>
                  <span v-else>{{ value }}</span>
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Create user modal -->
      <app-modal v-if="showCreateUser" title="Nouvel utilisateur" @close="showCreateUser = false">
        <form @submit.prevent="createUser">
          <div class="form-group">
            <label class="form-label">Nom d'utilisateur <span class="required">*</span></label>
            <input class="form-input" v-model="newUser.username" required placeholder="jean.dupont" />
          </div>
          <div class="form-group">
            <label class="form-label">Mot de passe <span class="required">*</span></label>
            <input class="form-input" type="password" v-model="newUser.password" required placeholder="••••••••" autocomplete="new-password" />
          </div>
          <div class="form-group">
            <label class="form-label">Rôle</label>
            <select class="form-select" v-model="newUser.role">
              <option v-for="r in roles" :key="r.value" :value="r.value">{{ r.label }}</option>
            </select>
          </div>
        </form>
        <template #footer>
          <button class="btn btn--secondary" @click="showCreateUser = false">Annuler</button>
          <button class="btn btn--primary" @click="createUser" :disabled="formLoading">
            <span v-if="formLoading" class="spinner spinner--sm"></span>
            <span v-else>Créer</span>
          </button>
        </template>
      </app-modal>
    </div>
  `,
}

/* ─── Root App ────────────────────────────────────────────────────────────── */

const App = {
  components: {
    DashboardView,
    ObjectsView,
    ClientsView,
    AuditView,
    AdminView,
    AppModal,
    StateBadge,
  },
  provide() {
    return {
      showToast: this.addToast,
      showConfirm: this.openConfirm,
    }
  },
  data() {
    return {
      state,
      currentView: 'DashboardView',
      sidebarOpen: false,
      loginForm: {
        username: '',
        password: '',
        totp: '',
        showPassword: false,
        totpVisible: false,
        requireTotp: false,
        loading: false,
        error: '',
      },
      toasts: [],
      toastIdCounter: 0,
      confirm: {
        visible: false,
        title: '',
        message: '',
        resolve: null,
      },
    }
  },
  computed: {
    viewTitle() {
      const map = {
        DashboardView: 'Tableau de bord',
        ObjectsView: 'Objets cryptographiques',
        ClientsView: 'Clients KMIP',
        AuditView: 'Journal d\'audit',
        AdminView: 'Administration',
      }
      return map[this.currentView] || ''
    },
    isAdmin() {
      return state.user && ['sec_admin', 'sys_admin'].includes(state.user.role)
    },
    roleLabel() {
      const map = { operator: 'Opérateur', auditor: 'Auditeur', sec_admin: 'Admin sécurité', sys_admin: 'Admin système' }
      return state.user ? (map[state.user.role] || state.user.role) : ''
    },
    roleBadgeClass() {
      const map = { operator: 'badge--gray', auditor: 'badge--blue', sec_admin: 'badge--warning', sys_admin: 'badge--danger' }
      return state.user ? (map[state.user.role] || 'badge--gray') : 'badge--gray'
    },
  },
  async mounted() {
    if (state.token) {
      try {
        const me = await api('GET', '/auth/me')
        if (me) {
          state.user = me
        } else {
          logout()
        }
      } catch {
        logout()
      }
    }
  },
  methods: {
    navigate(view) {
      this.currentView = view
      this.sidebarOpen = false
    },
    async handleLogin() {
      this.loginForm.loading = true
      this.loginForm.error = ''
      try {
        const body = {
          username: this.loginForm.username,
          password: this.loginForm.password,
        }
        if (this.loginForm.totp) body.totp = this.loginForm.totp

        const res = await api('POST', '/auth/login', body)
        if (res && res.access_token) {
          state.token = res.access_token
          localStorage.setItem('kms_token', state.token)
          const me = await api('GET', '/auth/me')
          if (me) state.user = me
          this.currentView = 'DashboardView'
        } else if (res && res.require_totp) {
          this.loginForm.requireTotp = true
          this.loginForm.totpVisible = true
          this.loginForm.error = 'Veuillez saisir votre code TOTP.'
        } else {
          this.loginForm.error = 'Réponse inattendue du serveur.'
        }
      } catch (e) {
        this.loginForm.error = e.message || 'Identifiants incorrects.'
      } finally {
        this.loginForm.loading = false
      }
    },
    handleLogout() {
      logout()
      this.loginForm = {
        username: '', password: '', totp: '',
        showPassword: false, totpVisible: false, requireTotp: false,
        loading: false, error: '',
      }
    },
    addToast(message, type = 'info') {
      const id = ++this.toastIdCounter
      this.toasts.push({ id, message, type })
      setTimeout(() => this.removeToast(id), 5000)
    },
    removeToast(id) {
      const i = this.toasts.findIndex(t => t.id === id)
      if (i !== -1) this.toasts.splice(i, 1)
    },
    openConfirm(title, message) {
      return new Promise(resolve => {
        this.confirm = { visible: true, title, message, resolve: (val) => {
          this.confirm.visible = false
          resolve(val)
        }}
      })
    },
    truncate,
  },
}

Vue.createApp(App).mount('#app')
