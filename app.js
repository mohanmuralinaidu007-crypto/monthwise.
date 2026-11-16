const STORAGE_KEY = "monthwise.expenses.v1";
const EMI_STORAGE_KEY = "monthwise.emis.v1";
const CARD_STORAGE_KEY = "monthwise.cards.v1";
const CURRENCY_KEY = "monthwise.currency.v1";
const VAULT_KEY = "monthwise.vault.v1";
const PBKDF2_ITERATIONS = 600000;
const IDLE_TIMEOUT = 5 * 60 * 1000;
const categories = {
  income: {
    Salary: { symbol: "↙", color: "#78a98a" },
    Reimbursement: { symbol: "↩", color: "#8e9dc0" },
    Overtime: { symbol: "＋", color: "#d59b74" },
    Freelance: { symbol: "✳", color: "#8e9dc0" },
    Business: { symbol: "◇", color: "#d59b74" },
    Investment: { symbol: "↗", color: "#74aaa4" },
    Gift: { symbol: "♡", color: "#c28d9b" },
    Other: { symbol: "•", color: "#a2aaa3" }
  },
  expense: {
    "Food & drink": { symbol: "⌂", color: "#78a98a" },
    Transport: { symbol: "↗", color: "#8e9dc0" },
    Shopping: { symbol: "◇", color: "#d59b74" },
    Bills: { symbol: "≋", color: "#c28d9b" },
    Health: { symbol: "+", color: "#74aaa4" },
    Entertainment: { symbol: "♪", color: "#a48fc1" },
    EMI: { symbol: "↻", color: "#8e9dc0" },
    "Credit Card": { symbol: "▭", color: "#c28d9b" },
    Other: { symbol: "•", color: "#a2aaa3" }
  }
};

const monthPicker = document.querySelector("#month-picker");
const currencyPicker = document.querySelector("#currency");
const transactionList = document.querySelector("#transaction-list");
const transactionFilter = document.querySelector("#transaction-filter");
const incomeCategorySummary = document.querySelector("#income-category-summary");
const spendingCategorySummary = document.querySelector("#category-summary");
const monthlyIncome = document.querySelector("#monthly-income");
const monthlySpent = document.querySelector("#monthly-spent");
const monthlyBalance = document.querySelector("#monthly-balance");
const incomeCount = document.querySelector("#income-count");
const spentCount = document.querySelector("#spent-count");
const transactionDialog = document.querySelector("#transaction-dialog");
const transactionForm = document.querySelector("#transaction-form");
const typePicker = document.querySelector("#transaction-type");
const categoryPicker = document.querySelector("#transaction-category");
const emiDialog = document.querySelector("#emi-dialog");
const emiForm = document.querySelector("#emi-form");
const cardDialog = document.querySelector("#credit-card-dialog");
const cardForm = document.querySelector("#credit-card-form");
const notice = document.querySelector("#notice");
const formError = document.querySelector("#form-error");
const appContent = document.querySelector("#app-content");
const lockScreen = document.querySelector("#lock-screen");
const lockForm = document.querySelector("#lock-form");
const lockError = document.querySelector("#lock-error");
const lockPin = document.querySelector("#pin-input");
const lockPinConfirm = document.querySelector("#pin-confirm");
const lockPinConfirmField = document.querySelector("#pin-confirm-field");
const lockSubmit = document.querySelector("#lock-submit");

let transactions = [];
let emis = [];
let creditCards = [];
let currency = "INR";
let vaultKey = null;
let vaultRecord = null;
let persistenceQueue = Promise.resolve();
let idleTimer = null;
let failedPinAttempts = 0;
let pinBlockedUntil = 0;
let isSettingUpVault = false;

function localDateString(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function isMonthKey(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}$/.test(value)) return false;
  const month = Number(value.slice(5, 7));
  return month >= 1 && month <= 12;
}

function showNotice(message) {
  notice.textContent = message;
  notice.hidden = false;
}

function formatMoney(value) {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency,
    maximumFractionDigits: 2
  }).format(value);
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function deriveEncryptionKey(pin, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(pin),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function getVaultData() {
  return JSON.stringify({ version: 1, transactions, emis, creditCards, currency });
}

async function encryptAndStore(snapshot, key, record) {
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      textEncoder.encode(snapshot)
    );
    const nextRecord = {
      version: 1,
      salt: record.salt,
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext))
    };
    localStorage.setItem(VAULT_KEY, JSON.stringify(nextRecord));
    vaultRecord = nextRecord;
    notice.hidden = true;
    return true;
  } catch (error) {
    showNotice("Could not securely save your data on this device. Your last saved copy is unchanged.");
    console.error("Unable to encrypt and save app data:", error);
    return false;
  }
}

function saveVault() {
  if (!vaultKey || !vaultRecord) return Promise.resolve(false);
  const snapshot = getVaultData();
  const operation = persistenceQueue.then(() =>
    encryptAndStore(snapshot, vaultKey, vaultRecord)
  );
  persistenceQueue = operation.then(() => undefined, () => undefined);
  return operation;
}

function readList(key, label) {
  const saved = localStorage.getItem(key);
  if (saved === null) return [];
  const parsed = JSON.parse(saved);
  if (!Array.isArray(parsed)) throw new TypeError(`Saved ${label} are not a list.`);
  return parsed;
}

function sanitizeTransactions(items) {
  if (!Array.isArray(items)) throw new TypeError("Encrypted transactions are not a list.");
  const valid = items
    .filter((transaction) =>
      transaction &&
      typeof transaction.id === "string" &&
      typeof transaction.name === "string" &&
      typeof transaction.category === "string" &&
      typeof transaction.date === "string" &&
      Number.isFinite(transaction.amount) &&
      transaction.amount > 0 &&
      (transaction.type === undefined || transaction.type === "income" || transaction.type === "expense")
    )
    .map((transaction) => ({
      ...transaction,
      type: transaction.type === "income" ? "income" : "expense"
    }));
  if (valid.length !== items.length) throw new TypeError("Some saved transactions are invalid.");
  return valid;
}

function loadTransactions() {
  return sanitizeTransactions(readList(STORAGE_KEY, "transactions"));
}

function sanitizeEmis(items) {
  if (!Array.isArray(items)) throw new TypeError("Encrypted EMI details are not a list.");
  const valid = items
    .filter((emi) =>
      emi &&
      typeof emi.id === "string" &&
      typeof emi.name === "string" &&
      typeof emi.bank === "string" &&
      Number.isFinite(emi.amount) &&
      emi.amount > 0 &&
      Number.isInteger(emi.months) &&
      emi.months > 0 &&
      Number.isInteger(emi.dueDay) &&
      emi.dueDay >= 1 &&
      emi.dueDay <= 31 &&
      isMonthKey(emi.startMonth)
    )
    .map((emi) => ({
      ...emi,
      closedFrom: isMonthKey(emi.closedFrom) ? emi.closedFrom : null
    }));
  if (valid.length !== items.length) throw new TypeError("Some saved EMI details are invalid.");
  return valid;
}

function loadEmis() {
  return sanitizeEmis(readList(EMI_STORAGE_KEY, "EMI details"));
}

function sanitizeCreditCards(items) {
  if (!Array.isArray(items)) throw new TypeError("Encrypted credit card details are not a list.");
  const valid = items
    .filter((card) =>
      card &&
      typeof card.id === "string" &&
      typeof card.name === "string" &&
      Number.isFinite(card.limit) &&
      card.limit >= 0
    )
    .map((card) => {
      const dues = {};
      if (card.dues && typeof card.dues === "object" && !Array.isArray(card.dues)) {
        for (const [month, due] of Object.entries(card.dues)) {
          if (isMonthKey(month) && Number.isFinite(due) && due >= 0) dues[month] = due;
        }
      }
      return {
        ...card,
        dues,
        archivedFrom: isMonthKey(card.archivedFrom) ? card.archivedFrom : null
      };
    });
  if (valid.length !== items.length) throw new TypeError("Some saved credit card details are invalid.");
  return valid;
}

function loadCreditCards() {
  return sanitizeCreditCards(readList(CARD_STORAGE_KEY, "credit card details"));
}

function validCurrency(value) {
  return ["INR", "USD", "EUR", "GBP"].includes(value);
}

function readVaultRecord() {
  const saved = localStorage.getItem(VAULT_KEY);
  if (saved === null) return null;
  const record = JSON.parse(saved);
  if (
    !record ||
    record.version !== 1 ||
    typeof record.salt !== "string" ||
    typeof record.iv !== "string" ||
    typeof record.ciphertext !== "string"
  ) {
    throw new TypeError("The encrypted vault record is incomplete.");
  }
  return record;
}

async function decryptVault(record, pin) {
  const salt = base64ToBytes(record.salt);
  const iv = base64ToBytes(record.iv);
  if (salt.length !== 16 || iv.length !== 12) throw new TypeError("The encrypted vault record is damaged.");
  const key = await deriveEncryptionKey(pin, salt);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    base64ToBytes(record.ciphertext)
  );
  const data = JSON.parse(textDecoder.decode(plaintext));
  if (
    !data ||
    data.version !== 1 ||
    !Array.isArray(data.transactions) ||
    !Array.isArray(data.emis) ||
    !Array.isArray(data.creditCards) ||
    !validCurrency(data.currency)
  ) {
    throw new TypeError("The encrypted vault data is invalid.");
  }
  const cleanTransactions = sanitizeTransactions(data.transactions);
  const cleanEmis = sanitizeEmis(data.emis);
  const cleanCards = sanitizeCreditCards(data.creditCards);
  return {
    key,
    data: {
      transactions: cleanTransactions,
      emis: cleanEmis,
      creditCards: cleanCards,
      currency: data.currency
    }
  };
}

function setLockMode(mode) {
  isSettingUpVault = mode === "setup";
  lockPinConfirmField.hidden = !isSettingUpVault;
  lockPinConfirm.required = isSettingUpVault;
  lockPin.autocomplete = isSettingUpVault ? "new-password" : "current-password";
  lockSubmit.textContent = isSettingUpVault ? "Create PIN and secure app" : "Unlock app";
  document.querySelector("#lock-title").textContent = isSettingUpVault
    ? "Create your app PIN"
    : "Unlock your money tracker";
  document.querySelector("#lock-description").textContent = isSettingUpVault
    ? "Choose a 6-digit PIN. Your existing app data will be encrypted on this device."
    : "Enter your 6-digit PIN to decrypt and view your financial data.";
  lockError.hidden = true;
  lockForm.hidden = false;
  lockPin.value = "";
  lockPinConfirm.value = "";
}

function showLockError(message, fatal = false) {
  lockError.textContent = message;
  lockError.hidden = false;
  if (fatal) lockForm.hidden = true;
}

function legacyData() {
  const savedCurrency = localStorage.getItem(CURRENCY_KEY);
  return {
    transactions: loadTransactions(),
    emis: loadEmis(),
    creditCards: loadCreditCards(),
    currency: validCurrency(savedCurrency) ? savedCurrency : "INR"
  };
}

function showUnlockedApp(data, key, record) {
  transactions = data.transactions;
  emis = data.emis;
  creditCards = data.creditCards;
  currency = data.currency;
  currencyPicker.value = currency;
  vaultKey = key;
  vaultRecord = record;
  lockForm.reset();
  lockPinConfirmField.hidden = true;
  lockPinConfirm.required = false;
  isSettingUpVault = false;
  lockError.hidden = true;
  lockScreen.hidden = true;
  appContent.hidden = false;
  document.querySelector("#lock-button").hidden = false;
  updateCategoryOptions();
  render();
  resetIdleTimer();
}

async function createVault(pin) {
  let data;
  try {
    data = legacyData();
  } catch (error) {
    console.error("Unable to migrate existing app data:", error);
    showLockError("Existing data could not be safely migrated. It has not been changed.");
    return;
  }

  transactions = data.transactions;
  emis = data.emis;
  creditCards = data.creditCards;
  currency = data.currency;
  vaultRecord = {
    version: 1,
    salt: bytesToBase64(crypto.getRandomValues(new Uint8Array(16)))
  };

  try {
    vaultKey = await deriveEncryptionKey(pin, base64ToBytes(vaultRecord.salt));
    if (!await saveVault()) {
      vaultKey = null;
      vaultRecord = null;
      showLockError("The encrypted vault could not be saved. Your existing data has not been changed.");
      return;
    }
  } catch (error) {
    vaultKey = null;
    vaultRecord = null;
    console.error("Unable to create encrypted vault:", error);
    showLockError("The security lock could not be created. Please try again.");
    return;
  }

  let legacyCleanupFailed = false;
  try {
    for (const key of [STORAGE_KEY, EMI_STORAGE_KEY, CARD_STORAGE_KEY, CURRENCY_KEY]) {
      localStorage.removeItem(key);
    }
  } catch (error) {
    legacyCleanupFailed = true;
    console.error("Unable to remove unencrypted legacy data:", error);
  }

  showUnlockedApp(data, vaultKey, vaultRecord);
  if (legacyCleanupFailed) {
    showNotice("Your data is encrypted, but an older unencrypted copy could not be removed from this browser.");
  }
}

function resetIdleTimer() {
  clearTimeout(idleTimer);
  if (!vaultKey) return;
  idleTimer = setTimeout(() => {
    lockApp();
  }, IDLE_TIMEOUT);
}

async function lockApp() {
  if (!vaultKey) return;
  clearTimeout(idleTimer);
  await persistenceQueue;
  for (const modal of [transactionDialog, emiDialog, cardDialog]) {
    if (modal.open) modal.close();
  }
  transactionForm.reset();
  emiForm.reset();
  cardForm.reset();
  transactions = [];
  emis = [];
  creditCards = [];
  currency = "INR";
  currencyPicker.value = currency;
  updateCategoryOptions();
  render();
  vaultKey = null;
  vaultRecord = null;
  appContent.hidden = true;
  document.querySelector("#lock-button").hidden = true;
  lockScreen.hidden = false;
  setLockMode("unlock");
  lockPin.focus();
}

async function initializeLock() {
  if (!window.isSecureContext || !crypto.subtle) {
    showLockError("The security lock requires a secure connection. Open this app on localhost or an HTTPS website.", true);
    return;
  }
  try {
    const record = readVaultRecord();
    setLockMode(record ? "unlock" : "setup");
    lockPin.focus();
  } catch (error) {
    console.error("Unable to read encrypted vault metadata:", error);
    showLockError("The encrypted vault could not be read. Your data has not been changed.", true);
  }
}

lockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (Date.now() < pinBlockedUntil) {
    showLockError("Too many incorrect PIN attempts. Wait 30 seconds and try again.");
    return;
  }

  const pin = lockPin.value;
  if (!/^\d{6}$/.test(pin)) {
    showLockError("Enter a 6-digit PIN.");
    return;
  }
  if (isSettingUpVault && pin !== lockPinConfirm.value) {
    showLockError("The PINs do not match. Enter them again.");
    lockPinConfirm.value = "";
    lockPinConfirm.focus();
    return;
  }

  lockSubmit.disabled = true;
  try {
    if (isSettingUpVault) {
      await createVault(pin);
      return;
    }
    const record = readVaultRecord();
    if (!record) throw new TypeError("The encrypted vault is missing.");
    const unlocked = await decryptVault(record, pin);
    failedPinAttempts = 0;
    lockError.hidden = true;
    showUnlockedApp(unlocked.data, unlocked.key, record);
    lockForm.reset();
  } catch (error) {
    failedPinAttempts += 1;
    if (failedPinAttempts >= 5) {
      failedPinAttempts = 0;
      pinBlockedUntil = Date.now() + 30000;
    }
    console.error("Unable to unlock encrypted app data:", error);
    showLockError("Incorrect PIN or encrypted data could not be unlocked.");
    lockPin.value = "";
    lockPin.focus();
  } finally {
    lockSubmit.disabled = false;
  }
});

document.querySelector("#lock-button").addEventListener("click", () => {
  lockApp();
});

for (const eventName of ["pointerdown", "keydown", "touchstart", "scroll"]) {
  document.addEventListener(eventName, resetIdleTimer, { passive: true });
}

function monthOffset(startMonth, targetMonth) {
  const [startYear, startNumber] = startMonth.split("-").map(Number);
  const [targetYear, targetNumber] = targetMonth.split("-").map(Number);
  return (targetYear - startYear) * 12 + targetNumber - startNumber;
}

function shiftMonth(month, offset) {
  const [year, monthNumber] = month.split("-").map(Number);
  const shifted = new Date(year, monthNumber - 1 + offset, 1);
  return `${shifted.getFullYear()}-${String(shifted.getMonth() + 1).padStart(2, "0")}`;
}

function ordinal(day) {
  const remainder = day % 100;
  if (remainder >= 11 && remainder <= 13) return `${day}th`;
  switch (day % 10) {
    case 1: return `${day}st`;
    case 2: return `${day}nd`;
    case 3: return `${day}rd`;
    default: return `${day}th`;
  }
}

function monthDate(month, day) {
  const [year, monthNumber] = month.split("-").map(Number);
  const lastDay = new Date(year, monthNumber, 0).getDate();
  return `${month}-${String(Math.min(day, lastDay)).padStart(2, "0")}`;
}

function activeEmisForMonth(month) {
  return emis.flatMap((emi) => {
    const offset = monthOffset(emi.startMonth, month);
    if (
      offset < 0 ||
      offset >= emi.months ||
      (emi.closedFrom && month >= emi.closedFrom)
    ) return [];
    const monthsLeft = emi.months - offset;
    return [{ ...emi, monthsLeft }];
  });
}

function activeCardsForMonth(month) {
  return creditCards.filter((card) => !card.archivedFrom || month < card.archivedFrom);
}

function cardDueForMonth(card, month) {
  return card.dues[month] || 0;
}

function getMonthlyTransactions(month) {
  const manual = transactions.filter((transaction) => transaction.date.slice(0, 7) === month);
  const emiTransactions = activeEmisForMonth(month).map((emi) => ({
    id: `emi-${emi.id}-${month}`,
    name: emi.name,
    amount: emi.amount,
    date: monthDate(month, emi.dueDay),
    category: "EMI",
    type: "expense",
    source: "emi",
    detail: emi.bank
  }));
  const cardTransactions = activeCardsForMonth(month)
    .map((card) => ({ card, amount: cardDueForMonth(card, month) }))
    .filter(({ amount }) => amount > 0)
    .map(({ card, amount }) => ({
      id: `card-${card.id}-${month}`,
      name: card.name,
      amount,
      date: `${month}-01`,
      dateLabel: new Intl.DateTimeFormat(undefined, { month: "short", year: "numeric" })
        .format(new Date(`${month}-01T12:00:00`)),
      category: "Credit Card",
      type: "expense",
      source: "card",
      detail: "Monthly due"
    }));
  return [...manual, ...emiTransactions, ...cardTransactions]
    .sort((a, b) => b.date.localeCompare(a.date) || b.id.localeCompare(a.id));
}

function renderCategorySummary(items, container, emptyMessage) {
  const totals = new Map();
  for (const transaction of items) {
    totals.set(transaction.category, (totals.get(transaction.category) || 0) + transaction.amount);
  }

  const total = items.reduce((sum, transaction) => sum + transaction.amount, 0);
  const sorted = [...totals.entries()].sort((a, b) => b[1] - a[1]);
  container.replaceChildren();
  if (sorted.length === 0) {
    const empty = document.createElement("p");
    empty.className = "category-empty";
    empty.textContent = emptyMessage;
    container.append(empty);
    return;
  }

  for (const [name, amount] of sorted) {
    const item = document.createElement("div");
    item.className = "category-item";

    const top = document.createElement("div");
    top.className = "category-item-top";
    const label = document.createElement("span");
    label.className = "category-name";
    label.textContent = name;
    const value = document.createElement("span");
    value.className = "category-value";
    value.textContent = formatMoney(amount);
    top.append(label, value);

    const track = document.createElement("div");
    track.className = "category-track";
    track.setAttribute("aria-label", `${name}: ${Math.round((amount / total) * 100)}%`);
    const fill = document.createElement("div");
    fill.className = "category-fill";
    fill.style.width = `${Math.max(3, (amount / total) * 100)}%`;
    fill.style.backgroundColor = categories[items[0].type]?.[name]?.color || categories.expense.Other.color;
    track.append(fill);
    item.append(top, track);
    container.append(item);
  }
}

function makeCell(text, className = "") {
  const cell = document.createElement("td");
  cell.textContent = text;
  if (className) cell.className = className;
  return cell;
}

function renderEmptyTable(tbody, columns, message) {
  const row = document.createElement("tr");
  const cell = makeCell(message, "empty-cell");
  cell.colSpan = columns;
  row.append(cell);
  tbody.replaceChildren(row);
}

function addActionButton(container, label, action, id, destructive = false) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = destructive ? "table-action delete-action" : "table-action";
  button.textContent = label;
  button.dataset[action] = id;
  button.setAttribute("aria-label", `${label} ${id}`);
  container.append(button);
  return button;
}

function renderEmis(month) {
  const active = activeEmisForMonth(month);
  document.querySelector("#emi-monthly-total").textContent =
    formatMoney(active.reduce((sum, emi) => sum + emi.amount, 0));
  document.querySelector("#emi-remaining-total").textContent =
    formatMoney(active.reduce((sum, emi) => sum + emi.amount * emi.monthsLeft, 0));

  const tbody = document.querySelector("#emi-list");
  if (active.length === 0) {
    renderEmptyTable(tbody, 7, "No active EMIs for this month. Add one to track monthly payments.");
    return;
  }

  const rows = active.map((emi) => {
    const row = document.createElement("tr");
    row.append(
      makeCell(emi.name),
      makeCell(formatMoney(emi.amount), "numeric-cell"),
      makeCell(String(emi.monthsLeft)),
      makeCell(formatMoney(emi.amount * emi.monthsLeft), "numeric-cell"),
      makeCell(ordinal(emi.dueDay)),
      makeCell(emi.bank)
    );
    const actionsCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    addActionButton(actions, "Edit", "editEmi", emi.id);
    addActionButton(actions, "Close", "closeEmi", emi.id, true);
    actionsCell.append(actions);
    row.append(actionsCell);
    return row;
  });
  tbody.replaceChildren(...rows);
}

function renderCreditCards(month) {
  const active = activeCardsForMonth(month);
  const limitTotal = active.reduce((sum, card) => sum + card.limit, 0);
  const dueTotal = active.reduce((sum, card) => sum + cardDueForMonth(card, month), 0);
  document.querySelector("#card-limit-total").textContent = formatMoney(limitTotal);
  document.querySelector("#card-due-total").textContent = formatMoney(dueTotal);
  document.querySelector("#card-pending-total").textContent = formatMoney(limitTotal - dueTotal);

  const tbody = document.querySelector("#credit-card-list");
  if (active.length === 0) {
    renderEmptyTable(tbody, 5, "No credit cards added for this month.");
    return;
  }

  const rows = active.map((card) => {
    const due = cardDueForMonth(card, month);
    const row = document.createElement("tr");
    row.append(
      makeCell(card.name),
      makeCell(formatMoney(card.limit), "numeric-cell"),
      makeCell(formatMoney(due), "numeric-cell"),
      makeCell(formatMoney(card.limit - due), "numeric-cell")
    );
    const actionsCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    addActionButton(actions, "Edit", "editCard", card.id);
    const archive = addActionButton(actions, "Archive next month", "archiveCard", card.id, true);
    if (card.archivedFrom) {
      archive.disabled = true;
      archive.textContent = `Archived from ${card.archivedFrom}`;
      archive.setAttribute("aria-label", `Card archived from ${card.archivedFrom}`);
    }
    actionsCell.append(actions);
    row.append(actionsCell);
    return row;
  });
  tbody.replaceChildren(...rows);
}

function renderTransactions(monthTransactions) {
  const filter = transactionFilter.value;
  const visibleTransactions = filter === "all"
    ? monthTransactions
    : monthTransactions.filter((transaction) => transaction.type === filter);
  transactionList.replaceChildren();
  if (visibleTransactions.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    const illustration = document.createElement("div");
    illustration.className = "empty-illustration";
    illustration.setAttribute("aria-hidden", "true");
    illustration.textContent = "＋";
    const title = document.createElement("h3");
    title.textContent = filter === "all"
      ? "No transactions this month"
      : `No ${filter === "income" ? "income" : "spending"} this month`;
    const description = document.createElement("p");
    description.textContent = "Add a transaction to start tracking this month.";
    empty.append(illustration, title, description);
    transactionList.append(empty);
    return;
  }

  for (const transaction of visibleTransactions) {
    const row = document.createElement("article");
    row.className = `expense-row ${transaction.type}-row`;

    const main = document.createElement("div");
    main.className = "expense-main";
    const symbol = document.createElement("span");
    symbol.className = "expense-symbol";
    symbol.setAttribute("aria-hidden", "true");
    symbol.textContent = categories[transaction.type]?.[transaction.category]?.symbol || categories[transaction.type].Other.symbol;
    const description = document.createElement("div");
    description.className = "expense-description";
    const title = document.createElement("p");
    title.className = "expense-title";
    title.textContent = transaction.name;
    const meta = document.createElement("div");
    meta.className = "expense-meta";
    const category = document.createElement("span");
    category.textContent = transaction.category;
    const type = document.createElement("span");
    type.textContent = transaction.source
      ? transaction.detail
      : transaction.type === "income" ? "Income" : "Spent";
    const date = document.createElement("span");
    date.textContent = transaction.dateLabel || new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric"
    }).format(new Date(`${transaction.date}T12:00:00`));
    meta.append(category, type, date);
    description.append(title, meta);
    main.append(symbol, description);

    const trailing = document.createElement("div");
    trailing.className = "expense-trailing";
    const amount = document.createElement("p");
    amount.className = "expense-amount";
    amount.textContent = `${transaction.type === "income" ? "+" : "−"} ${formatMoney(transaction.amount)}`;
    trailing.append(amount);
    if (!transaction.source) {
      const remove = document.createElement("button");
      remove.className = "delete-button";
      remove.type = "button";
      remove.dataset.transactionId = transaction.id;
      remove.setAttribute("aria-label", `Delete ${transaction.name}`);
      remove.textContent = "×";
      trailing.append(remove);
    }
    row.append(main, trailing);
    transactionList.append(row);
  }
}

function render() {
  const month = monthPicker.value;
  renderEmis(month);
  renderCreditCards(month);

  const monthTransactions = getMonthlyTransactions(month);
  const incomeTransactions = monthTransactions.filter((transaction) => transaction.type === "income");
  const spendingTransactions = monthTransactions.filter((transaction) => transaction.type === "expense");
  const incomeTotal = incomeTransactions.reduce((sum, transaction) => sum + transaction.amount, 0);
  const spendingTotal = spendingTransactions.reduce((sum, transaction) => sum + transaction.amount, 0);

  monthlyIncome.textContent = formatMoney(incomeTotal);
  monthlySpent.textContent = formatMoney(spendingTotal);
  monthlyBalance.textContent = formatMoney(incomeTotal - spendingTotal);
  incomeCount.textContent = incomeTransactions.length === 1
    ? "1 income entry this month"
    : `${incomeTransactions.length} income entries this month`;
  spentCount.textContent = spendingTransactions.length === 1
    ? "1 spending entry this month"
    : `${spendingTransactions.length} spending entries this month`;

  renderCategorySummary(incomeTransactions, incomeCategorySummary, "Add income to see a breakdown.");
  renderCategorySummary(spendingTransactions, spendingCategorySummary, "Add spending to see a breakdown.");
  renderTransactions(monthTransactions);
}

function changeMonth(offset) {
  monthPicker.value = shiftMonth(monthPicker.value, offset);
  render();
}

function updateCategoryOptions() {
  const type = typePicker.value;
  const previousCategory = categoryPicker.value;
  categoryPicker.replaceChildren();
  for (const name of Object.keys(categories[type])) {
    if (type === "expense" && (name === "EMI" || name === "Credit Card")) continue;
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    categoryPicker.append(option);
  }
  if (categories[type][previousCategory]) categoryPicker.value = previousCategory;

  const isIncome = type === "income";
  document.querySelector("#dialog-title").textContent = isIncome ? "Add income" : "Add spending";
  document.querySelector("#transaction-name-label").textContent = isIncome ? "Where did it come from?" : "What was it for?";
  document.querySelector("#transaction-name").placeholder = isIncome ? "e.g. Monthly salary" : "e.g. Weekly groceries";
  transactionForm.querySelector(".submit-button").textContent = isIncome ? "Save income" : "Save spending";
}

function openTransactionDialog(type = "expense") {
  transactionForm.reset();
  formError.hidden = true;
  typePicker.value = type;
  updateCategoryOptions();
  const selectedMonth = monthPicker.value;
  const today = localDateString(new Date());
  document.querySelector("#transaction-date").value = today.slice(0, 7) === selectedMonth
    ? today
    : `${selectedMonth}-01`;
  transactionDialog.showModal();
  document.querySelector("#transaction-name").focus();
}

function openEmiDialog(emi = null) {
  emiForm.reset();
  document.querySelector("#emi-form-error").hidden = true;
  document.querySelector("#emi-id").value = emi?.id || "";
  document.querySelector("#emi-name").value = emi?.name || "";
  document.querySelector("#emi-amount").value = emi?.amount ?? "";
  const monthsLeft = emi
    ? activeEmisForMonth(monthPicker.value).find((active) => active.id === emi.id)?.monthsLeft
    : "";
  document.querySelector("#emi-months").value = monthsLeft || emi?.months || "";
  document.querySelector("#emi-day").value = emi?.dueDay || "";
  document.querySelector("#emi-bank").value = emi?.bank || "";
  document.querySelector("#emi-dialog-title").textContent = emi ? "Edit EMI" : "Add an EMI";
  emiForm.querySelector(".submit-button").textContent = emi ? "Save changes" : "Save EMI";
  emiDialog.showModal();
  document.querySelector("#emi-name").focus();
}

function openCardDialog(card = null) {
  cardForm.reset();
  document.querySelector("#card-form-error").hidden = true;
  document.querySelector("#card-id").value = card?.id || "";
  document.querySelector("#card-name").value = card?.name || "";
  document.querySelector("#card-limit").value = card?.limit ?? "";
  document.querySelector("#card-due").value = card ? cardDueForMonth(card, monthPicker.value) : "";
  document.querySelector("#card-dialog-title").textContent = card ? "Edit credit card" : "Add a credit card";
  cardForm.querySelector(".submit-button").textContent = card ? "Save changes" : "Save credit card";
  cardDialog.showModal();
  document.querySelector("#card-name").focus();
}

document.querySelector("#previous-month").addEventListener("click", () => changeMonth(-1));
document.querySelector("#next-month").addEventListener("click", () => changeMonth(1));
monthPicker.addEventListener("change", render);
transactionFilter.addEventListener("change", render);
document.querySelector("#add-income").addEventListener("click", () => openTransactionDialog("income"));
document.querySelector("#add-spending").addEventListener("click", () => openTransactionDialog("expense"));
document.querySelector("#close-dialog").addEventListener("click", () => transactionDialog.close());
typePicker.addEventListener("change", updateCategoryOptions);
document.querySelector("#add-emi").addEventListener("click", () => openEmiDialog());
document.querySelector("#close-emi-dialog").addEventListener("click", () => emiDialog.close());
document.querySelector("#add-credit-card").addEventListener("click", () => openCardDialog());
document.querySelector("#close-card-dialog").addEventListener("click", () => cardDialog.close());

currencyPicker.addEventListener("change", async () => {
  const previous = currency;
  currency = currencyPicker.value;
  if (!await saveVault()) {
    currency = previous;
    currencyPicker.value = previous;
  }
  render();
});

transactionList.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-transaction-id]");
  if (!button) return;
  const previous = transactions;
  transactions = transactions.filter((transaction) => transaction.id !== button.dataset.transactionId);
  if (!await saveVault()) {
    transactions = previous;
    return;
  }
  render();
});

emiForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = document.querySelector("#emi-id").value;
  const name = document.querySelector("#emi-name").value.trim();
  const amount = Number(document.querySelector("#emi-amount").value);
  const months = Number(document.querySelector("#emi-months").value);
  const dueDay = Number(document.querySelector("#emi-day").value);
  const bank = document.querySelector("#emi-bank").value.trim();
  const error = document.querySelector("#emi-form-error");

  if (
    !name ||
    !Number.isFinite(amount) ||
    amount <= 0 ||
    !Number.isInteger(months) ||
    months < 1 ||
    !Number.isInteger(dueDay) ||
    dueDay < 1 ||
    dueDay > 31 ||
    !bank
  ) {
    error.textContent = "Enter an EMI name, a positive amount, months left, due day, and bank.";
    error.hidden = false;
    return;
  }

  const previous = emis;
  const existing = emis.find((emi) => emi.id === id);
  const updated = {
    id: existing?.id || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name,
    amount,
    months,
    dueDay,
    bank,
    startMonth: monthPicker.value,
    closedFrom: null
  };
  emis = existing
    ? emis.map((emi) => emi.id === id ? updated : emi)
    : [...emis, updated];
  if (!await saveVault()) {
    emis = previous;
    return;
  }
  emiDialog.close();
  render();
});

document.querySelector("#emi-list").addEventListener("click", async (event) => {
  const editButton = event.target.closest("button[data-edit-emi]");
  if (editButton) {
    const emi = emis.find((item) => item.id === editButton.dataset.editEmi);
    if (emi) openEmiDialog(emi);
    return;
  }
  const closeButton = event.target.closest("button[data-close-emi]");
  if (!closeButton) return;
  const previous = emis;
  emis = emis.map((emi) => emi.id === closeButton.dataset.closeEmi
    ? { ...emi, closedFrom: monthPicker.value }
    : emi);
  if (!await saveVault()) {
    emis = previous;
    return;
  }
  render();
});

cardForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = document.querySelector("#card-id").value;
  const name = document.querySelector("#card-name").value.trim();
  const limit = Number(document.querySelector("#card-limit").value);
  const due = Number(document.querySelector("#card-due").value);
  const error = document.querySelector("#card-form-error");

  if (!name || !Number.isFinite(limit) || limit < 0 || !Number.isFinite(due) || due < 0) {
    error.textContent = "Enter a card name and valid non-negative limit and due amounts.";
    error.hidden = false;
    return;
  }

  const previous = creditCards;
  const existing = creditCards.find((card) => card.id === id);
  const updated = {
    ...(existing || {}),
    id: existing?.id || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name,
    limit,
    dues: { ...(existing?.dues || {}), [monthPicker.value]: due }
  };
  creditCards = existing
    ? creditCards.map((card) => card.id === id ? updated : card)
    : [...creditCards, updated];
  if (!await saveVault()) {
    creditCards = previous;
    return;
  }
  cardDialog.close();
  render();
});

document.querySelector("#credit-card-list").addEventListener("click", async (event) => {
  const editButton = event.target.closest("button[data-edit-card]");
  if (editButton) {
    const card = creditCards.find((item) => item.id === editButton.dataset.editCard);
    if (card) openCardDialog(card);
    return;
  }
  const archiveButton = event.target.closest("button[data-archive-card]");
  if (!archiveButton || archiveButton.disabled) return;
  const previous = creditCards;
  const archiveFrom = shiftMonth(monthPicker.value, 1);
  creditCards = creditCards.map((card) => card.id === archiveButton.dataset.archiveCard
    ? { ...card, archivedFrom: archiveFrom }
    : card);
  if (!await saveVault()) {
    creditCards = previous;
    return;
  }
  render();
});

transactionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const type = typePicker.value;
  const amount = Number(document.querySelector("#transaction-amount").value);
  const name = document.querySelector("#transaction-name").value.trim();
  const date = document.querySelector("#transaction-date").value;
  const category = categoryPicker.value;

  if (
    !name ||
    !Number.isFinite(amount) ||
    amount <= 0 ||
    !date ||
    !categories[type] ||
    !categories[type][category]
  ) {
    formError.textContent = "Enter a description, a positive amount, a date, and a category.";
    formError.hidden = false;
    return;
  }

  const previous = transactions;
  transactions = [...transactions, {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type,
    name,
    amount,
    date,
    category
  }];
  if (!await saveVault()) {
    transactions = previous;
    return;
  }
  transactionDialog.close();
  monthPicker.value = date.slice(0, 7);
  render();
});

monthPicker.value = localDateString(new Date()).slice(0, 7);
updateCategoryOptions();
initializeLock();

if ("serviceWorker" in navigator && window.location.protocol !== "file:") {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./service-worker.js").catch((error) => {
      console.error("Unable to register offline support:", error);
    });
  });
}
