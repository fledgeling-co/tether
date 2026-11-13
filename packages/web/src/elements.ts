// Drop-in Web Components: <tether-pair> pairs this browser with a computer, and
// <tether-workspace> lists paired computers with their state and services. Every word they show
// comes from the Rust core, so they say what the Swift, Compose and WinUI screens say.
//
// Theme them with CSS custom properties on the element (--tether-accent, --tether-ink,
// --tether-secondary, --tether-ground, --tether-surface, --tether-line, --tether-success,
// --tether-warning, --tether-danger, --tether-radius, --tether-font) or style the exposed parts.
import { TetherError } from "./core.js";
import { TetherClient, HostService } from "./client.js";
import type { PeerRecord } from "./store.js";
import type { CloudRoute } from "./session.js";

const clients = new Map<string, Promise<TetherClient>>();
/** The shared client for an app, so every element on the page sees the same hosts. */
export function clientFor(appId: string): Promise<TetherClient> {
  let client = clients.get(appId);
  if (!client) {
    client = TetherClient.create({ appId });
    clients.set(appId, client);
  }
  return client;
}

const STYLE = `
:host{
  /* light-dark() follows the page's color-scheme: dark only when the page opts in. */
  --_accent:var(--tether-accent,light-dark(#0067d1,#4c9dff));--_on-accent:var(--tether-on-accent,light-dark(#ffffff,#06213f));
  --_ink:var(--tether-ink,light-dark(#1f2022,#ececee));--_secondary:var(--tether-secondary,light-dark(#5b5e64,#a7aab1));
  --_ground:var(--tether-ground,light-dark(#ffffff,#1c1d1f));--_surface:var(--tether-surface,light-dark(#f4f5f7,#2a2b2e));
  --_line:var(--tether-line,light-dark(#c9ccd2,#4a4c51));--_success:var(--tether-success,light-dark(#1d6b3c,#5fc684));
  --_warning:var(--tether-warning,light-dark(#7a4b00,#f0b45a));--_danger:var(--tether-danger,light-dark(#b0201f,#ff8a82));
  --_on-danger:light-dark(#ffffff,#2b0707);
  --_radius:var(--tether-radius,10px);
  display:block;color:var(--_ink);font:15px/1.45 var(--tether-font,-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif);
}
@supports not (color:light-dark(#000,#fff)){:host{
  --_accent:var(--tether-accent,#0067d1);--_on-accent:var(--tether-on-accent,#fff);--_ink:var(--tether-ink,#1f2022);
  --_secondary:var(--tether-secondary,#5b5e64);--_ground:var(--tether-ground,#fff);--_surface:var(--tether-surface,#f4f5f7);
  --_line:var(--tether-line,#c9ccd2);--_success:var(--tether-success,#1d6b3c);--_warning:var(--tether-warning,#7a4b00);
  --_danger:var(--tether-danger,#b0201f);--_on-danger:#fff;
}}
*{box-sizing:border-box}
[hidden]{display:none!important}
h2{font-size:20px;line-height:1.25;margin:0 0 6px;letter-spacing:-.01em}
h3{font-size:15px;margin:0}
p{margin:0}
.message{color:var(--_secondary);max-width:60ch}
.stack{display:grid;gap:16px}
label{display:grid;gap:6px;font-weight:600;font-size:13px}
input{font:inherit;font-weight:400;color:var(--_ink);background:var(--_ground);border:1px solid var(--_line);border-radius:8px;padding:9px 11px;min-height:40px;width:100%}
input:hover:not(:disabled){border-color:var(--_secondary)}
input:focus-visible{outline:2px solid var(--_accent);outline-offset:1px;border-color:var(--_accent)}
input:disabled{opacity:.6}
input[aria-invalid=true]{border-color:var(--_danger)}
.code input{font:600 20px/1 ui-monospace,"SF Mono",Menlo,Consolas,monospace;letter-spacing:.12em;text-transform:uppercase;max-width:15ch}
.hint{font-weight:400;color:var(--_secondary);font-size:13px}
.hint.bad{color:var(--_danger)}
.alert{display:flex;gap:10px;align-items:flex-start;padding:10px 12px;border-radius:8px;background:color-mix(in srgb,var(--_warning) 10%,var(--_ground));color:var(--_ink);border:1px solid color-mix(in srgb,var(--_warning) 40%,transparent)}
.alert::before{content:"!";flex:none;display:grid;place-items:center;width:18px;height:18px;margin-top:2px;border-radius:50%;background:var(--_warning);color:var(--_ground);font:700 12px/1 system-ui}
.success{color:var(--_success)}
.actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap}
button{font:inherit;font-weight:600;min-height:40px;padding:0 16px;border-radius:8px;border:1px solid var(--_line);background:var(--_ground);color:var(--_ink);cursor:pointer;display:inline-flex;align-items:center;gap:8px}
button:hover:not(:disabled){background:var(--_surface)}
button:active:not(:disabled){transform:translateY(1px)}
button:focus-visible{outline:2px solid var(--_accent);outline-offset:2px}
button:disabled{opacity:.55;cursor:not-allowed}
button.primary{background:var(--_accent);border-color:var(--_accent);color:var(--_on-accent)}
button.primary:hover:not(:disabled){background:color-mix(in srgb,var(--_accent) 86%,var(--_ink))}
button.quiet{border-color:transparent;background:transparent;color:var(--_accent);padding:0 8px}
button.danger{color:var(--_danger)}
.spinner{width:14px;height:14px;border-radius:50%;border:2px solid currentColor;border-right-color:transparent;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
@media (prefers-reduced-motion:reduce){.spinner{animation:none;border-right-color:currentColor;opacity:.6}}
details summary{cursor:pointer;color:var(--_accent);font-weight:600;font-size:14px;width:max-content}
details summary:focus-visible{outline:2px solid var(--_accent);outline-offset:2px;border-radius:4px}
details[open] summary{margin-bottom:12px}
`;

function element<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, unknown> = {}, ...children: (Node | string | null | undefined)[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value as EventListener);
    else if (key in node && !key.includes("-")) (node as any)[key] = value;
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children) if (child !== null && child !== undefined) node.append(child);
  return node;
}

type View = Record<string, any>;
/** Fixed copy from the core (`ui.strings`). */
type StringKey =
  | "add_title" | "workspace_title" | "workspace_empty" | "services" | "services_empty" | "check" | "recover"
  | "discard" | "rename" | "leave" | "leave_message" | "forget" | "forget_message" | "invitation_label"
  | "invitation_placeholder" | "use_invitation" | "details" | "relay_label" | "host_id_label" | "cancel" | "done"
  | "browser_title" | "browser_message" | "save" | "name_label" | "pairing_busy";
type Strings = Record<StringKey, string>;

abstract class TetherElement extends HTMLElement {
  protected root: ShadowRoot;
  protected tether?: TetherClient;
  protected text = {} as Strings;

  constructor() {
    super();
    this.root = this.attachShadow({ mode: "open" });
    this.root.append(element("style", {}, STYLE));
  }

  /** Use a specific client instead of the shared one for `app-id`. */
  set client(value: TetherClient) {
    this.tether = value;
    void this.start();
  }
  get client(): TetherClient | undefined {
    return this.tether;
  }

  connectedCallback() {
    void this.start();
  }

  private starting?: Promise<void>;
  protected start(): Promise<void> {
    if (this.starting) return this.starting;
    // Without a client or an app-id there's nothing to show yet; setting `client` starts it.
    if (!this.tether && !this.getAttribute("app-id")) return Promise.resolve();
    this.starting = (async () => {
      if (!this.tether) this.tether = await clientFor(this.getAttribute("app-id")!);
      this.text = this.tether.core.call<Strings>("ui.strings", { device: this.getAttribute("device") ?? "browser" });
      this.render();
    })().catch((error) => {
      this.starting = undefined;
      this.root.append(element("p", { role: "alert", class: "alert" }, error instanceof TetherError ? error.code : "Tether couldn't start."));
    });
    return this.starting;
  }

  protected abstract render(): void;

  protected replace(...nodes: Node[]) {
    const style = this.root.querySelector("style")!;
    this.root.replaceChildren(style, ...nodes);
  }
}

/** Pairs this browser with a computer by invitation link or code. Fires `tether-paired` and `tether-cancel`. */
export class TetherPairElement extends TetherElement {
  static observedAttributes = ["relay-url", "host-id", "invitation"];
  private state: "entry" | "checking" | "storing" | "connected" | "failed" = "entry";
  private abort?: AbortController;

  /** True once the acknowledgement is going out: closing now would leave the pairing half-done. */
  get committing(): boolean {
    return this.state === "storing";
  }
  private error?: string;
  private code = "";
  private invitation = "";
  private relay = "";
  private hostId = "";

  attributeChangedCallback() {
    this.invitation = this.getAttribute("invitation") ?? this.invitation;
    if (this.tether) this.render();
  }

  /** Stops any pairing still cancellable, clears what was typed and returns to entry. */
  reset() {
    this.abort?.abort();
    this.abort = undefined;
    this.state = "entry";
    this.error = undefined;
    this.code = this.invitation = this.relay = this.hostId = "";
    this.render();
  }

  private fixedRoute(): CloudRoute | undefined {
    const relayUrl = this.getAttribute("relay-url");
    const hostId = this.getAttribute("host-id");
    return relayUrl && hostId ? { mode: "cloud", relayUrl, hostId } : undefined;
  }

  private invitationState(): "empty" | "valid" | "invalid" {
    if (!this.invitation.trim()) return "empty";
    try {
      this.tether!.readInvitation(this.invitation.trim());
      return "valid";
    } catch {
      return "invalid";
    }
  }

  private route(): CloudRoute | undefined {
    const fixed = this.fixedRoute();
    if (fixed) return fixed;
    return this.tether!.checkRoute({ mode: "cloud", relayUrl: this.relay, hostId: this.hostId }) as CloudRoute | undefined;
  }

  private async submit() {
    const tether = this.tether!;
    const usingInvitation = this.invitationState() === "valid";
    const abort = new AbortController();
    this.abort = abort;
    this.state = "checking";
    this.error = undefined;
    this.render();
    const options = {
      signal: abort.signal,
      onProgress: (step: string) => {
        if (step === "storing" && this.abort === abort) {
          this.state = "storing";
          this.render();
        }
      },
    };
    try {
      const record = usingInvitation
        ? await tether.pairInvitation(this.invitation.trim(), options)
        : await tether.pair(this.route()!, this.code, options);
      if (this.abort !== abort) return;
      this.abort = undefined;
      this.state = "connected";
      this.code = this.invitation = "";
      this.render();
      this.dispatchEvent(new CustomEvent("tether-paired", { detail: record, bubbles: true, composed: true }));
    } catch (error) {
      // A reset already moved on; a cancelled pairing has nothing to report.
      if (this.abort !== abort) return;
      this.abort = undefined;
      this.state = "failed";
      this.error = error instanceof TetherError ? error.code : "invalid_protocol";
      this.render();
    }
  }

  private field(name: string): HTMLInputElement | null {
    return this.root.querySelector(`[data-field="${name}"]`);
  }

  private ready(): boolean {
    if (this.invitationState() === "valid") return true;
    const code = this.tether!.core.call<View>("ui.pair_code", { state: "entry", text: this.code });
    return code.field.valid && this.route() !== undefined;
  }

  /** Re-reads what is typed and updates hints and the button, leaving the inputs alone. */
  private update() {
    const tether = this.tether;
    if (!tether || this.state === "checking" || this.state === "storing" || this.state === "connected") return;
    const view: View = tether.core.call("ui.pair_code", { state: "entry", text: this.code });
    const invitation = this.invitationState();
    const ready = this.ready();
    const code = this.field("code");
    const hint = this.root.getElementById("code-hint");
    if (code && hint) {
      code.setAttribute("aria-invalid", view.field.hint ? "true" : "false");
      hint.textContent = view.field.hint ?? "";
      hint.className = view.field.hint ? "hint bad" : "hint";
    }
    const link = this.field("invitation");
    const linkHint = this.root.getElementById("invitation-hint");
    if (link && linkHint) {
      link.setAttribute("aria-invalid", invitation === "invalid" ? "true" : "false");
      linkHint.textContent = invitation === "invalid" ? tether.core.call<{ message: string }>("ui.error", { code: "invalid_invitation" }).message : "";
      linkHint.className = invitation === "invalid" ? "hint bad" : "hint";
      for (const name of ["relay", "host", "code"]) {
        const input = this.field(name);
        if (input) input.disabled = invitation === "valid";
      }
    }
    const primary = this.root.querySelector<HTMLButtonElement>('[part="primary"]');
    if (primary) primary.disabled = !ready;
  }

  protected render() {
    const tether = this.tether;
    if (!tether) return;
    const t = this.text;
    const view: View = tether.core.call("ui.pair_code", { state: this.state, peer: this.getAttribute("peer") ?? "", text: this.code, error: this.error });
    const fixed = this.fixedRoute();
    const busy = this.state === "checking" || this.state === "storing";
    const done = this.state === "connected";
    const input = (name: string, value: string, set: (value: string) => void, extra: Record<string, unknown> = {}) =>
      element("input", {
        "data-field": name, value, spellcheck: "false", autocomplete: "off", disabled: busy, ...extra,
        oninput: (e: Event) => { set((e.target as HTMLInputElement).value); this.update(); },
      });
    const codeField = () =>
      element("label", { class: "code" }, view.field.label,
        input("code", this.code, (v) => (this.code = v), {
          autocomplete: "one-time-code", autocapitalize: "characters", maxlength: 12, "aria-describedby": "code-hint",
        }),
        element("span", { id: "code-hint", class: "hint", "aria-live": "polite" }));
    const form = element("form", {
      class: "stack", part: "form", novalidate: true,
      onsubmit: (e: Event) => {
        e.preventDefault();
        if (done) {
          this.dispatchEvent(new CustomEvent("tether-done", { bubbles: true, composed: true }));
          this.reset();
        } else if (!busy && this.ready()) void this.submit();
      },
    });
    if (!done) {
      if (fixed) form.append(codeField());
      else {
        form.append(
          element("label", {}, t.invitation_label,
            input("invitation", this.invitation, (v) => (this.invitation = v), { placeholder: t.invitation_placeholder, "aria-describedby": "invitation-hint" }),
            element("span", { id: "invitation-hint", class: "hint", "aria-live": "polite" })),
          element("details", { open: this.relay || this.hostId ? true : undefined, part: "details" },
            element("summary", {}, t.details),
            element("div", { class: "stack" },
              element("label", {}, t.relay_label, input("relay", this.relay, (v) => (this.relay = v.trim()), { placeholder: "wss://relay.example/v1/relay", autocomplete: "url" })),
              element("label", {}, t.host_id_label, input("host", this.hostId, (v) => (this.hostId = v.trim()))),
              codeField())));
      }
    }
    if (this.state === "failed") form.append(element("p", { class: "alert", role: "alert", part: "error" }, view.message));
    form.append(element("div", { class: "actions" },
      view.secondary ? element("button", {
        type: "button", part: "secondary", disabled: !view.secondary.enabled,
        onclick: () => { this.reset(); this.dispatchEvent(new CustomEvent("tether-cancel", { bubbles: true, composed: true })); },
      }, view.secondary.label) : null,
      element("button", { type: "submit", class: "primary", part: "primary", disabled: busy },
        busy ? element("span", { class: "spinner", "aria-hidden": "true" }) : null,
        busy ? t.pairing_busy : view.primary?.label ?? t.done)));
    const browserEntry = this.state === "entry" && !fixed;
    this.replace(element("section", { class: "stack", part: "sheet", "aria-busy": busy ? "true" : "false" },
      element("div", { "aria-live": "polite" },
        element("h2", { class: view.tone === "success" ? "success" : undefined, part: "title" }, browserEntry ? t.browser_title : view.title),
        this.state === "failed" ? null : element("p", { class: "message" }, browserEntry ? t.browser_message : view.message)),
      form));
    this.update();
  }
}

interface HostRow {
  record: PeerRecord;
  state: string;
  services?: HostService[];
  checking: boolean;
}

/** Paired computers, their connection state and services. Fires `tether-hosts-changed`. */
export class TetherWorkspaceElement extends TetherElement {
  private rows = new Map<string, HostRow>();
  private dialog?: HTMLDialogElement;
  private content?: HTMLDivElement;
  private notice?: string;

  async refresh() {
    const tether = this.tether;
    if (!tether) return;
    const records = await tether.records();
    const next = new Map<string, HostRow>();
    for (const record of records) {
      const old = this.rows.get(record.hostKey);
      next.set(record.hostKey, old ? { ...old, record } : { record, state: record.confirmed ? "offline" : "pending", checking: false });
    }
    this.rows = next;
    this.render();
    for (const row of next.values()) if (row.record.confirmed && !row.services && !row.checking) void this.check(row.record.hostKey);
  }

  protected start() {
    return super.start().then(() => this.refresh());
  }

  private async check(hostKey: string) {
    const row = this.rows.get(hostKey);
    if (!row) return;
    row.checking = true;
    row.state = "connecting";
    this.render();
    try {
      row.services = await this.tether!.status(row.record);
      row.state = "connected";
    } catch (error) {
      const code = error instanceof TetherError ? error.code : "";
      row.state = code === "peer_revoked" ? "revoked" : code === "identity_mismatch" ? "identity_mismatch" : code === "pairing_pending" ? "pending" : "offline";
    }
    row.checking = false;
    this.render();
  }

  private async act(work: () => Promise<unknown>) {
    this.notice = undefined;
    try {
      await work();
    } catch (error) {
      this.notice = this.tether!.core.call<{ message: string }>("ui.error", { code: error instanceof TetherError ? error.code : "", peer: "the computer" }).message;
    }
    await this.refresh();
    this.dispatchEvent(new CustomEvent("tether-hosts-changed", { bubbles: true, composed: true }));
  }

  private confirm(title: string, message: string, label: string): Promise<boolean> {
    return new Promise((resolve) => {
      const dialog = element("dialog", { part: "confirm", "aria-labelledby": "confirm-title" },
        element("form", { method: "dialog", class: "stack" },
          element("h2", { id: "confirm-title" }, title),
          element("p", { class: "message" }, message),
          element("div", { class: "actions" },
            element("button", { value: "cancel", autofocus: true }, this.text.cancel),
            element("button", { value: "ok", class: "primary danger-fill" }, label))));
      dialog.addEventListener("close", () => { resolve(dialog.returnValue === "ok"); dialog.remove(); });
      this.root.append(dialog);
      dialog.showModal();
    });
  }

  private ask(title: string, value: string): Promise<string | null> {
    return new Promise((resolve) => {
      const field = element("input", { value, maxlength: 48, autocomplete: "off" });
      const dialog = element("dialog", { part: "rename", "aria-labelledby": "rename-title" },
        element("form", { method: "dialog", class: "stack" },
          element("h2", { id: "rename-title" }, title),
          element("label", {}, this.text.name_label, field),
          element("div", { class: "actions" },
            element("button", { value: "cancel", formnovalidate: true }, this.text.cancel),
            element("button", { value: "ok", class: "primary" }, this.text.save))));
      dialog.addEventListener("close", () => { resolve(dialog.returnValue === "ok" ? field.value : null); dialog.remove(); });
      this.root.append(dialog);
      dialog.showModal();
      field.select();
    });
  }

  private openPairing() {
    if (!this.dialog) {
      const pair = new TetherPairElement();
      for (const name of ["relay-url", "host-id", "device"]) {
        const value = this.getAttribute(name);
        if (value) pair.setAttribute(name, value);
      }
      pair.client = this.tether!;
      this.dialog = element("dialog", { part: "pair-dialog", "aria-label": this.text.add_title }, pair);
      // Escape can't close it while the acknowledgement is going out.
      this.dialog.addEventListener("cancel", (event) => {
        if ((pair as TetherPairElement).committing) event.preventDefault();
      });
      const close = () => this.dialog?.close();
      pair.addEventListener("tether-cancel", close);
      pair.addEventListener("tether-done", close);
      pair.addEventListener("tether-paired", () => void this.refresh().then(() => this.dispatchEvent(new CustomEvent("tether-hosts-changed", { bubbles: true, composed: true }))));
      this.dialog.addEventListener("close", () => (pair as TetherPairElement).reset());
    }
    if (!this.dialog.isConnected) this.root.append(this.dialog);
    this.dialog.showModal();
  }

  protected render() {
    const tether = this.tether;
    if (!tether) return;
    const t = this.text;
    const list = element("ul", { class: "hosts", part: "hosts", "aria-label": t.workspace_title });
    for (const row of this.rows.values()) {
      const record = row.record;
      const state: View = tether.core.call("ui.connection_state", { state: row.state });
      const name = record.name ?? (record.route.mode === "cloud" ? `Computer ${record.route.hostId.slice(0, 4).toUpperCase()}` : "Computer");
      const buttons: (Node | null)[] = record.confirmed
        ? [
            element("button", { type: "button", class: "quiet", disabled: row.checking, onclick: () => void this.check(record.hostKey) }, t.check),
            element("button", { type: "button", class: "quiet", onclick: async () => {
              const value = await this.ask(t.rename, record.name ?? "");
              if (value !== null) void this.act(() => tether.rename(record, value));
            } }, t.rename),
            element("button", { type: "button", class: "quiet danger", onclick: async () => {
              if (await this.confirm(`${t.leave}?`, t.leave_message, t.leave)) void this.act(() => tether.leave(record));
            } }, t.leave),
            element("button", { type: "button", class: "quiet danger", onclick: async () => {
              if (await this.confirm(`${t.forget}?`, t.forget_message, t.forget)) void this.act(() => tether.forget(record));
            } }, t.forget),
          ]
        : [
            element("button", { type: "button", class: "primary", onclick: () => void this.act(() => tether.recover(record)) }, t.recover),
            element("button", { type: "button", class: "quiet danger", onclick: () => void this.act(() => tether.discardPending(record)) }, t.discard),
          ];
      list.append(element("li", { class: "host", part: "host" },
        element("div", { class: "host-head" },
          element("div", {},
            element("h3", {}, name),
            element("p", { class: `state ${state.tone}` },
              row.checking ? element("span", { class: "spinner", "aria-hidden": "true" }) : element("span", { class: "dot", "aria-hidden": "true" }),
              element("span", { "aria-label": `Connection status: ${state.title}` }, state.title))),
        ),
        element("p", { class: "message" }, state.explanation),
        record.confirmed ? element("div", { class: "services" },
          element("h4", {}, t.services),
          row.services?.length
            ? element("ul", {}, ...row.services.map((s) => element("li", {}, element("code", {}, s.id), element("span", { class: "kind" }, s.kind.toUpperCase()))))
            : element("p", { class: "hint" }, t.services_empty)) : null,
        element("div", { class: "row-actions" }, ...buttons)));
    }
    const empty = this.rows.size === 0
      ? element("div", { class: "empty", part: "empty" },
          element("p", { class: "message" }, t.workspace_empty),
          element("button", { type: "button", class: "primary", onclick: () => this.openPairing() }, t.add_title))
      : null;
    // Dialogs live beside the content, never inside it: moving an open modal dialog demotes it.
    if (!this.content) {
      this.content = element("div", { part: "workspace" });
      this.root.append(element("style", {}, WORKSPACE_STYLE), this.content);
    }
    this.content.replaceChildren(
      element("header", { class: "top" },
        element("h2", {}, t.workspace_title),
        this.rows.size ? element("button", { type: "button", class: "primary", part: "add", onclick: () => this.openPairing() }, element("span", { "aria-hidden": "true" }, "+"), t.add_title) : null),
      this.notice ? element("p", { class: "alert", role: "alert" }, this.notice) : element("span", { hidden: true }),
      empty ?? list,
    );
  }
}

const WORKSPACE_STYLE = `
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}
.top h2{margin:0}
.hosts{list-style:none;margin:0;padding:0;display:grid;gap:12px}
.host{background:var(--_ground);border:1px solid var(--_line);border-radius:var(--_radius);padding:16px;display:grid;gap:10px}
.host-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
.state{display:flex;align-items:center;gap:6px;font-size:13px;font-weight:600;margin-top:2px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--_secondary)}
.state.success{color:var(--_success)}.state.success .dot{background:var(--_success)}
.state.warning{color:var(--_warning)}.state.warning .dot{background:var(--_warning)}
.state.danger{color:var(--_danger)}.state.danger .dot{background:var(--_danger)}
.state.neutral{color:var(--_secondary)}
.services h4{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--_secondary);margin:4px 0 6px}
.services ul{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:6px}
.services li{display:inline-flex;gap:8px;align-items:center;background:var(--_surface);border-radius:6px;padding:4px 8px;font-size:13px}
.services code{font:13px ui-monospace,"SF Mono",Menlo,Consolas,monospace}
.kind{color:var(--_secondary);font-size:11px;font-weight:600}
.row-actions{display:flex;flex-wrap:wrap;gap:4px;margin:0 -8px -6px}
.row-actions button{min-height:36px;font-size:14px}
.row-actions button.primary{margin-left:8px}
.empty{border:1px dashed var(--_line);border-radius:var(--_radius);padding:32px 24px;display:grid;gap:10px;justify-items:start}
dialog{border:none;border-radius:14px;padding:24px;background:var(--_ground);color:var(--_ink);width:min(480px,calc(100vw - 32px));box-shadow:0 20px 60px rgb(0 0 0/.28)}
dialog::backdrop{background:rgb(0 0 0/.36)}
.danger-fill{background:var(--_danger)!important;border-color:var(--_danger)!important;color:var(--_on-danger)!important}
.alert{margin-bottom:12px}
`;

if (typeof customElements !== "undefined") {
  if (!customElements.get("tether-pair")) customElements.define("tether-pair", TetherPairElement);
  if (!customElements.get("tether-workspace")) customElements.define("tether-workspace", TetherWorkspaceElement);
}
