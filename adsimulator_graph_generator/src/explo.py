import json
import random
from collections import defaultdict, deque

import ipywidgets as widgets
from IPython.display import display, HTML


DEFAULT_HIGH_VALUE_KEYWORDS = [
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS", "KRBTGT",
    "BACKUP OPERATORS", "SERVER OPERATORS", "ACCOUNT OPERATORS",
    "PRINT OPERATORS"
]

TYPE_COLORS = {
    "User": "#15803d",
    "Computer": "#1d4ed8",
    "Group": "#ca8a04",
    "OU": "#7e22ce",
    "GPO": "#dc2626",
    "Domain": "#9333ea",
    "Container": "#475569",
    "Other": "#334155",
}


def load_graph_zero(graph_path):
    adjacency_out = defaultdict(list)
    adjacency_in = defaultdict(list)
    node_types = {}

    with open(graph_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            data = json.loads(line)

            if data.get("type") == "node":
                props = data.get("properties", {})
                name = props.get("name", str(data.get("id")))
                labels = data.get("labels", [])

                node_type = "Other"
                for p in ["User", "Computer", "Group", "OU", "GPO", "Domain", "Container"]:
                    if p in labels:
                        node_type = p
                        break

                node_types[name] = node_type

            elif data.get("type") == "relationship":
                start = data.get("start", {}).get("properties", {}).get("name")
                end = data.get("end", {}).get("properties", {}).get("name")

                rel = (
                    data.get("label")
                    or data.get("properties", {}).get("type")
                    or data.get("properties", {}).get("name")
                    or "UNKNOWN"
                )

                if start and end:
                    adjacency_out[start].append({"node": end, "rel": rel, "direction": "out"})
                    adjacency_in[end].append({"node": start, "rel": rel, "direction": "in"})
                    node_types.setdefault(start, "Other")
                    node_types.setdefault(end, "Other")

    return adjacency_out, adjacency_in, node_types


def badge(text, color):
    return f"""
    <span style="
        display:inline-block;
        padding:3px 8px;
        border-radius:999px;
        color:white;
        background:{color};
        font-size:11px;
        font-weight:700;
    ">{text}</span>
    """


class SimpleADGame:
    def __init__(
        self,
        graph_path,
        max_turns=12,
        high_value_keywords=None,
        max_choices=10,
    ):
        self.graph_path = graph_path
        self.max_turns = max_turns
        self.high_value_keywords = high_value_keywords or DEFAULT_HIGH_VALUE_KEYWORDS
        self.max_choices = max_choices

        self.adj_out, self.adj_in, self.node_types = load_graph_zero(graph_path)

        self.users = [n for n, t in self.node_types.items() if t == "User"]
        if not self.users:
            raise ValueError("No User node found.")

        self.current = None
        self.path = []
        self.relations = []
        self.turn = 0
        self.score = 0
        self.game_over = False
        self.win = False

        self.header = widgets.HTML()
        self.moves = widgets.VBox()
        self.path_box = widgets.HTML()

        self.btn_new = widgets.Button(
            description="New game",
            button_style="success",
            layout=widgets.Layout(width="150px")
        )
        self.btn_back = widgets.Button(
            description="Back",
            button_style="warning",
            layout=widgets.Layout(width="150px")
        )
        self.mode = widgets.ToggleButtons(
            options=[("Outgoing", "out"), ("Both", "both")],
            value="out",
            description="Mode:",
            layout=widgets.Layout(width="360px")
        )

        self.btn_new.on_click(self.new_game)
        self.btn_back.on_click(self.back)

    def is_high_value(self, node):
        return any(k in node.upper() for k in self.high_value_keywords)

    def score_move(self, choice):
        node = choice["node"]
        rel = choice["rel"].upper()
        node_type = self.node_types.get(node, "Other")

        score = 0

        if self.is_high_value(node):
            score += 100

        if node_type == "Group":
            score += 12
        elif node_type == "Computer":
            score += 8
        elif node_type == "User":
            score += 4

        for word in ["ADMIN", "MEMBER", "GENERICALL", "WRITE", "DCSYNC", "RDP", "SESSION"]:
            if word in rel:
                score += 15
                break

        return score

    def node_potential(self, node, depth=3):
        visited = set()
        q = deque([(node, 0)])
        score = 0

        while q:
            cur, d = q.popleft()

            if cur in visited:
                continue
            visited.add(cur)

            if d > 0:
                score += 1

            if d > 0 and self.is_high_value(cur):
                score += 50

            if d >= depth:
                continue

            for e in self.adj_out.get(cur, []):
                q.append((e["node"], d + 1))

        return score

    def choose_start(self):
        candidates = []

        for user in self.users:
            if len(self.adj_out.get(user, [])) == 0:
                continue

            p = self.node_potential(user, depth=4)
            if p > 2:
                candidates.append((user, p))

        if candidates:
            candidates.sort(key=lambda x: x[1], reverse=True)
            return random.choice(candidates[:30])[0]

        return random.choice(self.users)

    def get_choices(self):
        choices = []

        for e in self.adj_out.get(self.current, []):
            c = dict(e)
            c["score"] = self.score_move(c) + self.node_potential(c["node"], depth=2)
            choices.append(c)

        if self.mode.value == "both":
            for e in self.adj_in.get(self.current, []):
                c = dict(e)
                c["score"] = self.score_move(c) + self.node_potential(c["node"], depth=2) - 5
                choices.append(c)

        visited_count = {n: self.path.count(n) for n in set(self.path)}
        for c in choices:
            c["score"] -= visited_count.get(c["node"], 0) * 10

        choices.sort(key=lambda x: x["score"], reverse=True)
        return choices[:self.max_choices]

    def move(self, choice):
        if self.win:
            return

        self.current = choice["node"]
        self.path.append(self.current)
        self.relations.append(choice["rel"])
        self.turn += 1
        self.score += max(0, int(choice["score"]))

        if self.is_high_value(self.current):
            self.win = True
            self.game_over = True
        elif self.turn >= self.max_turns:
            self.game_over = True
        else:
            self.game_over = False

        self.render()

    def new_game(self, _=None):
        self.current = self.choose_start()
        self.path = [self.current]
        self.relations = []
        self.turn = 0
        self.score = 0
        self.game_over = False
        self.win = False
        self.render()

    def back(self, _=None):
        if len(self.path) <= 1:
            return

        self.path.pop()

        if self.relations:
            self.relations.pop()

        self.current = self.path[-1]
        self.turn = max(0, self.turn - 1)
        self.score = max(0, self.score - 5)
        self.game_over = False
        self.win = False
        self.render()

    def render_header(self):
        node_type = self.node_types.get(self.current, "Other")
        color = TYPE_COLORS.get(node_type, TYPE_COLORS["Other"])

        if self.win:
            status = "<span style='color:#15803d;font-weight:800;'>VICTORY</span>"
        elif self.game_over:
            status = "<span style='color:#dc2626;font-weight:800;'>GAME OVER</span>"
        else:
            status = "<span style='color:#1d4ed8;font-weight:800;'>PLAYING</span>"

        self.header.value = f"""
        <div style="
            padding:14px;
            border:1px solid #cbd5e1;
            border-radius:12px;
            margin-bottom:12px;
            background:#ffffff;
            color:#111827;
        ">
            <h2 style="margin:0;color:#111827;">AD Attack Path Game</h2>
            <p style="margin:6px 0;color:#334155;">
                Goal: reach a high-value target in {self.max_turns} turns.
            </p>

            <div style="margin-top:10px;color:#111827;">
                <b>Current:</b> {self.current}<br>
                <b>Type:</b> {badge(node_type, color)}
                &nbsp; <b>Turn:</b> {self.turn}/{self.max_turns}
                &nbsp; <b>Score:</b> {self.score}
                &nbsp; <b>Status:</b> {status}
            </div>
        </div>
        """

    def render_moves(self):
        if self.win:
            self.moves.children = []
            return

        choices = self.get_choices()

        if not choices:
            self.game_over = True
            self.moves.children = [
                widgets.HTML("""
                <div style="
                    padding:12px;
                    background:#fee2e2;
                    color:#7f1d1d;
                    border:1px solid #fecaca;
                    border-radius:8px;
                    font-weight:700;
                ">
                    No move available. Use Back or New game.
                </div>
                """)
            ]
            return

        rows = []

        for i, c in enumerate(choices):
            node = c["node"]
            rel = c["rel"]
            direction = "→" if c["direction"] == "out" else "←"
            node_type = self.node_types.get(node, "Other")
            color = TYPE_COLORS.get(node_type, TYPE_COLORS["Other"])

            if self.is_high_value(node):
                quality = badge("TARGET", "#15803d")
            elif c["score"] >= 25:
                quality = badge("GOOD", "#1d4ed8")
            elif c["score"] >= 8:
                quality = badge("OK", "#ca8a04")
            else:
                quality = badge("RISKY", "#dc2626")

            text = widgets.HTML(f"""
            <div style="
                padding:10px;
                border:1px solid #e5e7eb;
                border-radius:8px;
                background:#ffffff;
                color:#111827;
                min-width:620px;
                margin-bottom:6px;
            ">
                <b>{i + 1}. {direction} {node}</b><br>
                <span style="font-size:12px;color:#334155;">
                    relation: <b>{rel}</b>
                    &nbsp; type: {badge(node_type, color)}
                    &nbsp; {quality}
                    &nbsp; score: {int(c["score"])}
                </span>
            </div>
            """)

            btn = widgets.Button(
                description="Move",
                layout=widgets.Layout(width="80px")
            )

            def handler(_, choice=c):
                self.move(choice)

            btn.on_click(handler)
            rows.append(widgets.HBox([text, btn]))

        self.moves.children = rows

    def render_path(self):
        blocks = []

        for i, node in enumerate(self.path):
            node_type = self.node_types.get(node, "Other")
            color = TYPE_COLORS.get(node_type, TYPE_COLORS["Other"])

            blocks.append(f"""
            <div style="
                display:inline-block;
                vertical-align:top;
                padding:10px 12px;
                margin:4px;
                border:2px solid {color};
                border-radius:10px;
                background:#ffffff;
                color:#111827;
                min-width:160px;
                max-width:220px;
            ">
                <div style="font-size:11px;color:#64748b;">Step {i}</div>
                <div style="font-weight:800;font-size:13px;word-break:break-word;">{node}</div>
                <div style="margin-top:6px;">{badge(node_type, color)}</div>
            </div>
            """)

            if i < len(self.relations):
                rel = self.relations[i]
                blocks.append(f"""
                <div style="
                    display:inline-block;
                    vertical-align:top;
                    margin:22px 4px;
                    color:#111827;
                    font-weight:800;
                ">
                    →<br>
                    <span style="font-size:11px;color:#475569;">{rel}</span>
                </div>
                """)

        self.path_box.value = f"""
        <div style="
            padding:12px;
            border:1px solid #cbd5e1;
            border-radius:12px;
            background:#f8fafc;
            color:#111827;
            overflow-x:auto;
            white-space:nowrap;
        ">
            {''.join(blocks)}
        </div>
        """

    def render(self):
        self.render_header()
        self.render_moves()
        self.render_path()

    def display(self):
        self.new_game()

        controls = widgets.HBox([
            self.btn_new,
            self.btn_back,
            self.mode
        ], layout=widgets.Layout(gap="6px", margin="0 0 10px 0"))

        ui = widgets.VBox([
            self.header,
            controls,
            widgets.HTML("<h3 style='color:#111827;'>Available moves</h3>"),
            self.moves,
            widgets.HTML("<h3 style='color:#111827;'>Current path</h3>"),
            self.path_box
        ])

        display(ui)