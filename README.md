# masterclass-dl

A command line tool to download masterclass.com classes.

## Features

- **Download entire categories** - Bulk download all classes from any category page
- **Plex-ready output** - Poster (`poster.jpg`) and fanart (`fanart.jpg`) images for media servers
- **Embedded subtitles** - 10+ languages automatically embedded in videos
- **PDF workbooks** - Class guides and supplementary materials
- **Flexible options** - Control what gets downloaded with `--pdfs`, `--posters`, `--limit`

## Prerequisites

- yt-dlp (recommended) or youtube-dl
- ffmpeg

## Installation

Download the executable from the [releases](https://github.com/RythenGlyth/masterclass-dl/releases) page.

Or build from source:
```bash
go build -o masterclass-dl .
```

## Usage

### Login

First, authenticate with your Masterclass account:

```bash
masterclass-dl login <email> <password>
```

You'll be prompted to select a profile if your account has multiple profiles.

### Check Status

Verify your login and subscription status:

```bash
masterclass-dl status
```

### Download

Download individual classes, specific chapters, or **bulk download entire categories**:

```bash
# Download a single class
masterclass-dl download -o ./downloads "https://www.masterclass.com/classes/gordon-ramsay-teaches-cooking"

# Download a specific chapter
masterclass-dl download -o ./downloads "https://www.masterclass.com/classes/gordon-ramsay-teaches-cooking/chapters/introduction"

# Download all classes in a category (first 10 by default)
masterclass-dl download -o ./downloads "https://www.masterclass.com/homepage/science-and-tech"

# Download all classes in a category (no limit)
masterclass-dl download -o ./downloads --limit 0 "https://www.masterclass.com/homepage/science-and-tech"
```

#### Download Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | (required) | Output directory |
| `--limit` | `-l` | 10 | Max classes to download from a category (0 = unlimited) |
| `--pdfs` | `-p` | true | Download PDF workbooks |
| `--posters` | | true | Download poster and fanart images |
| `--ytdl-exec` | `-y` | yt-dlp | Path to yt-dlp/youtube-dl executable |

#### Examples

```bash
# Download without PDFs
masterclass-dl download -o ./downloads --pdfs=false "https://www.masterclass.com/classes/gordon-ramsay-teaches-cooking"

# Download without poster images
masterclass-dl download -o ./downloads --posters=false "https://www.masterclass.com/classes/gordon-ramsay-teaches-cooking"

# Download first 5 classes from a category
masterclass-dl download -o ./downloads --limit 5 "https://www.masterclass.com/homepage/science-and-tech"

# Use a specific yt-dlp path
masterclass-dl download -o ./downloads -y /usr/local/bin/yt-dlp "https://www.masterclass.com/classes/gordon-ramsay-teaches-cooking"
```

### Output Structure

Downloads are organized in a Plex/Jellyfin-friendly format:

```
downloads/
├── Gordon Ramsay Teaches Cooking/
│   ├── poster.jpg              # 2x3 vertical artwork (for Plex/Jellyfin)
│   ├── fanart.jpg              # 16x9 horizontal artwork (for backgrounds)
│   ├── Class Guide.pdf         # Workbook/PDF materials
│   ├── 001-Introduction.mp4    # Video with embedded subtitles
│   ├── 002-Knives.mp4
│   └── ...
└── Neil deGrasse Tyson.../
    └── ...
```

**Video features:**
- Embedded subtitles in 10+ languages (English, Spanish, French, German, Italian, Japanese, Chinese, Hindi, Polish, Portuguese)
- Best available video/audio quality
- Metadata embedded (title, description, episode number)

## Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--datDir` | `-d` | ~/.masterclass/ | Directory for cookies and data |
| `--debug` | | false | Enable debug output |

## Commands Reference

```
masterclass-dl [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  download    Download a class, chapter, or category from masterclass.com
  help        Help about any command
  login       Login to masterclass.com
  status      Check login status

Use "masterclass-dl [command] --help" for more information about a command.
```
