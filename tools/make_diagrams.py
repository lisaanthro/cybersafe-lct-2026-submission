#!/usr/bin/env python3
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyBboxPatch, FancyArrowPatch

out = Path(__file__).resolve().parents[1] / 'images'
out.mkdir(exist_ok=True)

plt.rcParams.update({'font.family': 'DejaVu Sans'})
fig, ax = plt.subplots(figsize=(10, 2.6), dpi=180)
ax.set_xlim(0, 2.0)
ax.set_ylim(0, 1)
ax.axis('off')
ax.add_patch(Rectangle((0, .28), 1, .34, facecolor='#ddd6fe', edgecolor='#4c1d95', lw=1.5))
ax.add_patch(Rectangle((1, .28), 1, .34, facecolor='#fef3c7', edgecolor='#92400e', lw=1.5))
ax.text(.5, .48, 'Прошивка + таблицы + настройки\n0x10000000 … 0x100fffff', ha='center', va='center', fontsize=10)
ax.text(1.5, .48, 'Закодированный FAT12, 1 МиБ\n0x10100000 … 0x101fffff', ha='center', va='center', fontsize=10)
ax.annotate('PIN 8170\n0x10005500', xy=(.02125, .62), xytext=(.18, .9), arrowprops={'arrowstyle':'->'}, ha='center', fontsize=9)
ax.annotate('cmp/BNE\n0x10000c8a/0x10000c8c', xy=(.0032, .28), xytext=(.38, .08), arrowprops={'arrowstyle':'->'}, ha='center', fontsize=9)
ax.text(0, .2, 'offset 0x000000', ha='left', fontsize=8)
ax.text(1, .2, 'offset 0x100000', ha='center', fontsize=8)
ax.text(2, .2, 'offset 0x200000', ha='right', fontsize=8)
fig.tight_layout()
fig.savefig(out / 'memory-map.png', bbox_inches='tight')
plt.close(fig)

fig, ax = plt.subplots(figsize=(10, 3), dpi=180)
ax.set_xlim(0, 10)
ax.set_ylim(0, 3)
ax.axis('off')
items = [
    ('BOOT + RESET', .15, '#e0e7ff'),
    ('PICOBOOT\nPC_READ', 2.15, '#ddd6fe'),
    ('дамп 2 МиБ', 4.15, '#dbeafe'),
    ('XOR по\nизвестной формуле', 6.15, '#fef3c7'),
    ('валидный\nFAT12', 8.15, '#dcfce7'),
]
for label, x, color in items:
    ax.add_patch(FancyBboxPatch((x, 1.05), 1.7, .9, boxstyle='round,pad=.08,rounding_size=.08', facecolor=color, edgecolor='#334155', lw=1.3))
    ax.text(x+.85, 1.5, label, ha='center', va='center', fontsize=10)
for (_, x1, _), (_, x2, _) in zip(items, items[1:]):
    ax.add_patch(FancyArrowPatch((x1+1.72, 1.5), (x2-.03, 1.5), arrowstyle='-|>', mutation_scale=13, color='#334155'))
ax.text(5, .45, 'PIN в этой цепочке вообще не используется', ha='center', va='center', fontsize=11, color='#991b1b', weight='bold')
fig.tight_layout()
fig.savefig(out / 'attack-chain.png', bbox_inches='tight')
plt.close(fig)
