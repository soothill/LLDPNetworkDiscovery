#!/bin/bash
# Check the quality metrics of generated visualization files

echo "============================================================"
echo "LLDP Network Discovery - Image Quality Check"
echo "============================================================"
echo ""

# Check if files exist
if [ ! -f "network_topology.png" ]; then
    echo "❌ network_topology.png not found"
    echo "   Run: python3 lldp_discovery.py homedevices.json"
    exit 1
fi

# PNG Quality Check
echo "📊 PNG Quality Metrics:"
echo "------------------------------------------------------------"

# Get file size
png_size=$(du -h network_topology.png | cut -f1)
echo "File size: $png_size"

# Check DPI using identify (ImageMagick)
if command -v identify &> /dev/null; then
    echo ""
    echo "Resolution info:"
    identify -verbose network_topology.png | grep -A2 "Resolution:"
    identify -verbose network_topology.png | grep "Geometry:"

    # Extract DPI
    dpi=$(identify -verbose network_topology.png | grep "Resolution:" | head -1 | awk '{print $2}')
    dpi_value=$(echo $dpi | cut -d'x' -f1)

    echo ""
    if [ "$dpi_value" -ge 600 ]; then
        echo "✅ DPI: $dpi (Excellent - Professional quality)"
    elif [ "$dpi_value" -ge 300 ]; then
        echo "⚠️  DPI: $dpi (Good - Consider regenerating for higher quality)"
    else
        echo "❌ DPI: $dpi (Low - Please regenerate with latest code)"
    fi
else
    echo "⚠️  ImageMagick not installed. Install with:"
    echo "   Ubuntu/Debian: sudo apt install imagemagick"
    echo "   macOS: brew install imagemagick"
fi

echo ""
echo "------------------------------------------------------------"

# SVG Check
if [ -f "network_topology.svg" ]; then
    echo ""
    echo "📐 SVG (Vector) Metrics:"
    echo "------------------------------------------------------------"
    svg_size=$(du -h network_topology.svg | cut -f1)
    echo "File size: $svg_size"
    echo "✅ SVG is infinitely scalable - use this for best quality!"
    echo "   View in browser: open network_topology.svg"
    echo ""
else
    echo ""
    echo "❌ network_topology.svg not found"
    echo "   Update to latest code and regenerate"
    echo ""
fi

# D3.js Interactive Check
if [ -f "network_topology_d3.html" ]; then
    echo "------------------------------------------------------------"
    echo ""
    echo "🌐 Interactive Visualizations:"
    echo "------------------------------------------------------------"
    d3_size=$(du -h network_topology_d3.html | cut -f1)
    echo "D3.js interactive: $d3_size"
    echo "   Open: open network_topology_d3.html"

    if [ -f "network_topology.html" ]; then
        html_size=$(du -h network_topology.html | cut -f1)
        echo "Static HTML: $html_size"
        echo "   Open: open network_topology.html"
    fi
    echo ""
fi

# Recommendations
echo "============================================================"
echo "💡 Recommendations:"
echo "============================================================"
echo ""
echo "Best quality visualization:"
echo "  1. Use SVG for viewing (infinite zoom, always crisp)"
echo "  2. Use D3.js for interactive exploration"
echo "  3. Use PNG (600 DPI) for presentations/documents"
echo ""
echo "If PNG text is still too small:"
echo "  • Use SVG and zoom in"
echo "  • Convert SVG to higher DPI PNG:"
echo "    inkscape network_topology.svg --export-png=ultra.png --export-dpi=1200"
echo ""
echo "View SVG now:"
echo "  open network_topology.svg"
echo ""
