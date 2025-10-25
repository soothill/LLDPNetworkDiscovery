# Network Topology Visualization Guide

## Output Files

When you run `lldp_discovery.py`, you get multiple visualization formats:

1. **network_topology.svg** - Vector format (RECOMMENDED for best quality)
2. **network_topology.png** - High-resolution raster (600 DPI)
3. **network_topology.html** - Interactive static HTML
4. **network_topology_d3.html** - Interactive D3.js force-directed graph
5. **topology.json** - Raw data

## Best Quality: Use SVG

### Why SVG is Better

- ✅ **Infinitely scalable** - zoom without quality loss
- ✅ **Crisp text at any size** - always perfectly sharp
- ✅ **Smaller file size** - typically 10-50% of PNG size
- ✅ **Editable** - can modify in Inkscape or Illustrator
- ✅ **Searchable text** - can search for device names

### How to View SVG

**Option 1: Web Browser (Easiest)**
```bash
# Open in your default browser
open network_topology.svg          # macOS
xdg-open network_topology.svg      # Linux
start network_topology.svg         # Windows
```

**Option 2: Inkscape (Best for editing)**
```bash
sudo apt install inkscape          # Ubuntu/Debian
brew install inkscape              # macOS

inkscape network_topology.svg
```

**Option 3: Convert to Ultra-High Resolution PNG**
```bash
# Convert SVG to 1200 DPI PNG
inkscape network_topology.svg --export-png=topology_1200dpi.png --export-dpi=1200

# Convert SVG to 2400 DPI PNG (extreme quality)
inkscape network_topology.svg --export-png=topology_2400dpi.png --export-dpi=2400
```

## PNG Quality Settings

The PNG output is configured for:
- **600 DPI** - Professional print quality
- **30x20 inch** base size (scales with network size)
- **Anti-aliased text** - smooth fonts
- **Large fonts** - minimum 8-16pt depending on network size

### Checking PNG Resolution

```bash
# Check PNG file info
file network_topology.png
identify -verbose network_topology.png | grep -i resolution

# Expected output: Resolution: 600x600
```

### If PNG Still Looks Blurry

1. **Make sure you pulled the latest code**:
   ```bash
   cd ~/LLDPNetworkDiscovery
   git pull
   ```

2. **Clear matplotlib cache**:
   ```bash
   rm -rf ~/.matplotlib
   rm -rf ~/.cache/matplotlib
   ```

3. **Regenerate the visualization**:
   ```bash
   source venv/bin/activate
   python3 lldp_discovery.py homedevices.json
   ```

4. **Use SVG instead** - it's always perfect quality!

## Interactive Visualizations

### D3.js Interactive Graph

Open `network_topology_d3.html` in a browser:
- **Drag** nodes to rearrange
- **Zoom** with mouse wheel
- **Click** nodes to highlight connections
- **Hover** for details

### Static HTML

Open `network_topology.html` in a browser:
- Color-coded by device type
- Connection table with port speeds
- Click device names to filter

## Troubleshooting

### "Text is too small"

**Solution 1**: Use SVG and zoom in
**Solution 2**: Generate higher DPI PNG from SVG:
```bash
inkscape network_topology.svg --export-png=ultra_hd.png --export-dpi=2400
```

### "Network too large, labels overlap"

The layout algorithm spreads nodes based on size. For very large networks:

**Solution 1**: Use the interactive D3.js visualization:
```bash
open network_topology_d3.html
# Drag nodes to arrange them better
```

**Solution 2**: Edit the SVG manually in Inkscape
**Solution 3**: View the JSON data directly:
```bash
jq . topology.json | less
```

### "PNG file is huge"

This is expected! High DPI = larger files.
- 600 DPI PNG: ~2-10 MB (depending on network size)
- SVG: typically smaller ~500 KB - 2 MB

**Solution**: Use SVG for storage, convert to PNG only when needed.

## File Size Comparison

Example for a 20-device network:

| Format | File Size | Quality | Use Case |
|--------|-----------|---------|----------|
| SVG | 800 KB | Perfect | Best for viewing, editing, archiving |
| PNG (600 DPI) | 4.2 MB | Excellent | Presentations, documents |
| PNG (1200 DPI) | 15 MB | Extreme | Large format printing |
| HTML | 50 KB | Interactive | Web viewing |
| D3.js | 120 KB | Interactive | Network exploration |
| JSON | 25 KB | Data only | Programmatic access |

## Recommended Workflow

1. **Generate all formats**:
   ```bash
   python3 lldp_discovery.py homedevices.json
   ```

2. **Quick view** - Open SVG in browser:
   ```bash
   open network_topology.svg
   ```

3. **For presentations** - Use 600 DPI PNG (already generated)

4. **For detailed analysis** - Use D3.js interactive:
   ```bash
   open network_topology_d3.html
   ```

5. **For printing** - Convert SVG to higher DPI if needed:
   ```bash
   inkscape network_topology.svg --export-png=print.png --export-dpi=1200
   ```

6. **For editing** - Open SVG in Inkscape and customize

## Tips for Large Networks

For networks with 50+ devices:

1. Use the **D3.js interactive visualization** - you can drag nodes apart
2. Use **SVG and zoom** in specific areas
3. Consider **filtering the JSON** to show subsets:
   ```bash
   # Show only connections to a specific device
   jq '.connections[] | select(.local_device == "core-switch")' topology.json
   ```

4. Use the **HTML table view** for a searchable list

## Questions?

- SVG won't open? Install a modern browser or Inkscape
- Need even higher quality? Convert SVG at higher DPI
- Network too complex? Use interactive D3.js visualization
- Want to customize? Edit SVG in Inkscape or code
