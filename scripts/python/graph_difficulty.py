#!/usr/bin/env python3
import sys
import os
import argparse

def parse_difficulty_data(input_source):
    """
    Reads and parses difficulty data from a file-like object.
    
    Args:
        input_source: A file-like object (e.g., an open file or sys.stdin).
    Returns:
        list: A list of dictionaries containing block height and difficulty.
    """
    data = []
    for line in input_source:
        line = line.strip()
        if not line:
            continue
        parts = line.split(':')
        if len(parts) == 2:
            try:
                block_height = int(parts[0].strip())
                difficulty = int(parts[1].strip())
                data.append({'block_height': block_height, 'difficulty': difficulty})
            except ValueError:
                continue
    return data

def generate_svg_graph(data, output_file):
    """
    Generates a line graph in an SVG file from a list of data.
    
    Args:
        data (list): A list of dictionaries with 'block_height' and 'difficulty'.
        output_file (str): Path for the output SVG image.
    """
    if not data:
        print("Error: No valid data to plot.")
        sys.exit(1)

    # Sort the data by block height in ascending order
    data.sort(key=lambda x: x['block_height'])

    # Get min/max values for scaling
    min_height = data[0]['block_height']
    max_height = data[-1]['block_height']
    min_difficulty = min(d['difficulty'] for d in data)
    max_difficulty = max(d['difficulty'] for d in data)

    # Handle the ZeroDivisionError case where all difficulties are the same
    difficulty_range = max_difficulty - min_difficulty
    if difficulty_range == 0:
        min_difficulty = min_difficulty - 100
        max_difficulty = max_difficulty + 100
        difficulty_range = max_difficulty - min_difficulty
    
    # SVG parameters
    width, height = 1200, 800
    left_margin, right_margin = 150, 50
    bottom_margin, top_margin = 50, 50
    
    plot_width = width - left_margin - right_margin
    plot_height = height - bottom_margin - top_margin

    # Generate SVG header
    svg_content = f"""<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
<rect x="0" y="0" width="{width}" height="{height}" fill="white"/>
<text x="{width / 2}" y="30" font-family="sans-serif" font-size="20" text-anchor="middle" fill="black">Difficulty by Block Height</text>
<text x="{left_margin + plot_width / 2}" y="{height - 10}" font-family="sans-serif" font-size="14" text-anchor="middle" fill="black">Block Height</text>
<text x="30" y="{top_margin + plot_height / 2}" font-family="sans-serif" font-size="14" text-anchor="middle" transform="rotate(-90 30,{top_margin + plot_height / 2})" fill="black">Difficulty</text>
<line x1="{left_margin}" y1="{height - bottom_margin}" x2="{width - right_margin}" y2="{height - bottom_margin}" stroke="black" stroke-width="2"/>
<line x1="{left_margin}" y1="{height - bottom_margin}" x2="{left_margin}" y2="{top_margin}" stroke="black" stroke-width="2"/>
"""
    # Plot points as a polyline
    points = []
    scale_x = plot_width / (max_height - min_height) if (max_height - min_height) != 0 else 1
    scale_y = plot_height / difficulty_range
    for d in data:
        x = left_margin + (d['block_height'] - min_height) * scale_x
        y = (height - bottom_margin) - (d['difficulty'] - min_difficulty) * scale_y
        points.append(f"{x},{y}")
    
    svg_content += f"""<polyline points="{' '.join(points)}" style="fill:none;stroke:blue;stroke-width:2" />"""

    # Add X-axis ticks and labels
    num_x_ticks = 10
    x_interval = (max_height - min_height) / num_x_ticks
    for i in range(num_x_ticks + 1):
        tick_value = round(min_height + i * x_interval)
        x_pos = left_margin + (tick_value - min_height) * scale_x
        svg_content += f"""<line x1="{x_pos}" y1="{height - bottom_margin}" x2="{x_pos}" y2="{height - bottom_margin + 5}" stroke="black" />"""
        svg_content += f"""<text x="{x_pos}" y="{height - bottom_margin + 20}" font-family="sans-serif" font-size="10" text-anchor="middle" fill="black">{tick_value}</text>"""

    # Add Y-axis ticks and labels
    num_y_ticks = 10
    y_interval = difficulty_range / num_y_ticks
    for i in range(num_y_ticks + 1):
        tick_value = round(min_difficulty + i * y_interval)
        y_pos = (height - bottom_margin) - (tick_value - min_difficulty) * scale_y
        
        # Format label for readability
        if tick_value >= 1e9:
            label = f'{tick_value * 1e-9:.2f}B'
        elif tick_value >= 1e6:
            label = f'{tick_value * 1e-6:.2f}M'
        elif tick_value >= 1e3:
            label = f'{tick_value * 1e-3:.2f}K'
        else:
            label = str(tick_value)

        svg_content += f"""<line x1="{left_margin - 5}" y1="{y_pos}" x2="{left_margin}" y2="{y_pos}" stroke="black" />"""
        svg_content += f"""<text x="{left_margin - 10}" y="{y_pos + 4}" font-family="sans-serif" font-size="10" text-anchor="end" fill="black">{label}</text>"""
    
    svg_content += "</svg>"

    with open(output_file, 'w') as f:
        f.write(svg_content)
    
    print(f"Graph successfully saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Generates graph from neptune-cli block-difficulties output",
        usage="%(prog)s [-o output_file] [input_file]"
    )
    parser.add_argument(
        '-o', '--output',
        dest='output_file',
        default='difficulty_by_block.svg',
        help='Specify the output file path (default: difficulty_by_block.svg)'
    )
    parser.add_argument(
        'input_file',
        nargs='?',
        help='Input file containing block difficulties. Reads from stdin if not specified.'
    )
    
    args = parser.parse_args()

    # Determine input source: file or stdin
    if args.input_file:
        if not os.path.exists(args.input_file):
            print(f"Error: The specified file '{args.input_file}' does not exist.", file=sys.stderr)
            sys.exit(1)
        
        with open(args.input_file, 'r') as f:
            data = parse_difficulty_data(f)
    elif not sys.stdin.isatty():
        # Handle pipe input from stdin
        data = parse_difficulty_data(sys.stdin)
    else:
        # No input file and no pipe, print help message and exit
        parser.print_help()

        print("Example:")
        print("  neptune-cli block-difficulties tip | ./graph_difficulty.py")
        sys.exit(1)

    # Generate the graph with the determined output file name
    generate_svg_graph(data, args.output_file)

if __name__ == "__main__":
    main()
