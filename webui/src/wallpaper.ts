// WebUI background wallpaper. The default image is fetched from the cloud
// server so it can be updated without rebuilding the module; a user-selected
// image is stored only on this device (IndexedDB) and becomes the local
// default. No user image is ever uploaded.

export const DEFAULT_WALLPAPER_URL = 'https://omk.5ijxa.com/bz.jpg'
export const MAX_WALLPAPER_BYTES = 10 * 1024 * 1024
export const WALLPAPER_ERROR_TOO_LARGE = 'too_large'

const ENABLED_STORAGE_KEY = 'omk-wallpaper-enabled'
const DB_NAME = 'omk-wallpaper'
const STORE_NAME = 'images'
const RECORD_KEY = 'current'

export type WallpaperSource = 'default' | 'custom'
export type WallpaperPickResult = 'updated' | 'cancelled'
type Listener = () => void

function readEnabled(): boolean {
  try {
    const value = window.localStorage.getItem(ENABLED_STORAGE_KEY)
    return value === null ? true : value === 'true'
  } catch {
    return true
  }
}

function storeEnabled(enabled: boolean): void {
  try {
    window.localStorage.setItem(ENABLED_STORAGE_KEY, String(enabled))
  } catch {
    // Storage may be unavailable in some WebViews; the in-memory state stands.
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = window.indexedDB.open(DB_NAME, 1)
    request.onupgradeneeded = () => {
      const database = request.result
      if (!database.objectStoreNames.contains(STORE_NAME)) database.createObjectStore(STORE_NAME)
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('Unable to open the wallpaper store'))
  })
}

async function withStore<T>(
  mode: IDBTransactionMode,
  action: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  const database = await openDatabase()
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, mode)
      const request = action(transaction.objectStore(STORE_NAME))
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error ?? new Error('Wallpaper store request failed'))
    })
  } finally {
    database.close()
  }
}

function validImageBlob(blob: Blob): boolean {
  return blob.size > 0 && blob.size <= MAX_WALLPAPER_BYTES && blob.type.startsWith('image/')
}

export class Wallpaper {
  #listeners = new Set<Listener>()
  #enabled = readEnabled()
  #source: WallpaperSource = 'default'
  #objectUrl: string | null = null
  #ready: Promise<void>
  #picking = false

  constructor() {
    this.#apply()
    this.#ready = this.#restore()
  }

  get enabled(): boolean { return this.#enabled }
  get source(): WallpaperSource { return this.#source }

  ready(): Promise<void> { return this.#ready }

  subscribe(listener: Listener): () => void {
    this.#listeners.add(listener)
    return () => this.#listeners.delete(listener)
  }

  setEnabled(enabled: boolean): void {
    if (enabled === this.#enabled) return
    this.#enabled = enabled
    storeEnabled(enabled)
    this.#apply()
    this.#emit()
  }

  // Opens the platform image picker, validates the choice, then persists it as
  // the local default. The picked image is applied immediately on success.
  async pickImage(): Promise<WallpaperPickResult> {
    if (this.#picking) return 'cancelled'
    this.#picking = true
    try {
      const file = await this.#selectImageFile()
      if (!file) return 'cancelled'
      if (!validImageBlob(file)) throw new Error(WALLPAPER_ERROR_TOO_LARGE)
      await this.#storeBlob(file)
      this.#useBlob(file)
      if (!this.#enabled) {
        this.#enabled = true
        storeEnabled(true)
      }
      this.#apply()
      this.#emit()
      return 'updated'
    } finally {
      this.#picking = false
    }
  }

  async resetDefault(): Promise<void> {
    try {
      await withStore('readwrite', store => store.delete(RECORD_KEY))
    } catch {
      // A failed delete still clears the in-memory override below.
    }
    if (this.#objectUrl !== null) {
      URL.revokeObjectURL(this.#objectUrl)
      this.#objectUrl = null
    }
    this.#source = 'default'
    this.#apply()
    this.#emit()
  }

  async #restore(): Promise<void> {
    let blob: Blob | null = null
    try {
      const stored = await withStore<Blob | undefined>('readonly', store => store.get(RECORD_KEY))
      if (stored instanceof Blob && validImageBlob(stored)) blob = stored
    } catch (error) {
      console.warn('Unable to restore the saved wallpaper:', error)
    }
    if (blob) {
      this.#useBlob(blob)
      this.#apply()
      this.#emit()
    }
  }

  #useBlob(blob: Blob): void {
    if (this.#objectUrl !== null) URL.revokeObjectURL(this.#objectUrl)
    this.#objectUrl = URL.createObjectURL(blob)
    this.#source = 'custom'
  }

  async #storeBlob(blob: Blob): Promise<void> {
    try {
      await withStore('readwrite', store => store.put(blob, RECORD_KEY))
    } catch (error) {
      console.warn('Unable to persist the wallpaper; it stays active for this session:', error)
    }
  }

  #selectImageFile(): Promise<File | null> {
    return new Promise(resolve => {
      const input = document.createElement('input')
      input.type = 'file'
      input.accept = 'image/*'
      input.setAttribute('aria-hidden', 'true')
      Object.assign(input.style, {
        position: 'fixed', width: '1px', height: '1px', opacity: '0', pointerEvents: 'none',
      })
      let settled = false
      const cleanup = (): void => { input.remove() }
      const finish = (value: File | null): void => {
        if (settled) return
        settled = true
        cleanup()
        resolve(value)
      }
      input.addEventListener('change', () => finish(input.files?.[0] ?? null), { once: true })
      input.addEventListener('cancel', () => finish(null), { once: true })
      document.body.appendChild(input)
      try {
        input.click()
      } catch (error) {
        console.error('Unable to open the image picker:', error)
        finish(null)
      }
    })
  }

  #apply(): void {
    const root = document.documentElement
    root.dataset.wallpaper = this.#enabled ? 'true' : 'false'
    if (!this.#enabled) {
      root.style.removeProperty('--omk-wallpaper-image')
      return
    }
    const url = this.#source === 'custom' && this.#objectUrl !== null
      ? this.#objectUrl
      : DEFAULT_WALLPAPER_URL
    root.style.setProperty('--omk-wallpaper-image', `url("${url}")`)
  }

  #emit(): void {
    for (const listener of this.#listeners) listener()
  }
}

export const wallpaper = new Wallpaper()
