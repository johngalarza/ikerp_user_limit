/** @odoo-module **/

import { registry } from "@web/core/registry";
import { rpc } from "@web/core/network/rpc";
import { Component, onWillStart, useState } from "@odoo/owl";

const POLL_INTERVAL_MS = 5 * 60 * 1000;

export class IkerpStorageBanner extends Component {
    static template = "ikerp_user_limit.StorageBanner";
    static props = {};

    setup() {
        this.state = useState({
            visible: false,
            level: "ok",
            pct: 0,
            usedMB: 0,
            limitMB: 0,
        });
        onWillStart(async () => {
            await this.refresh();
            setInterval(() => this.refresh(), POLL_INTERVAL_MS);
        });
    }

    async refresh() {
        try {
            const data = await rpc("/ikerp/storage/state");
            const level = data.state || "ok";
            this.state.visible = ["warning", "critical", "blocked"].includes(level);
            this.state.level = level;
            this.state.pct = Math.round((data.pct || 0) * 100);
            this.state.usedMB = data.usedMB || 0;
            this.state.limitMB = data.limitMB || 0;
        } catch (_e) {
            this.state.visible = false;
        }
    }

    get message() {
        const { level, pct, usedMB, limitMB } = this.state;
        if (level === "warning") {
            return `Has usado ${pct}% de tu almacenamiento (${usedMB}/${limitMB} MB). Considera ampliar tu plan.`;
        }
        if (level === "critical") {
            return `Estás al ${pct}% de tu almacenamiento. Si llegas al 100%, no podrás subir nuevos archivos.`;
        }
        if (level === "blocked") {
            return "Almacenamiento agotado. No se pueden crear nuevos adjuntos hasta liberar espacio o ampliar el plan.";
        }
        return "";
    }
}

registry.category("main_components").add("ikerp_user_limit.StorageBanner", {
    Component: IkerpStorageBanner,
});
