#!/bin/bash

echo "========================================"
echo "MediaPipe Solutions Fix Script"
echo "========================================"
echo ""

# Check if Python 3.11 is available
if command -v python3.11 &> /dev/null; then
    echo "✓ Python 3.11 found!"
    python3.11 --version
else
    echo "✗ Python 3.11 not found"
    echo ""
    echo "Install Python 3.11 first:"
    echo "  brew install python@3.11"
    echo ""
    echo "Or download from: https://www.python.org/downloads/"
    exit 1
fi

echo ""
echo "This will:"
echo "  1. Backup your current 'lift' folder to 'lift_backup'"
echo "  2. Create a new virtual environment with Python 3.11"
echo "  3. Install all required packages"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Backup old venv
if [ -d "lift" ]; then
    echo "Backing up old virtual environment..."
    mv lift lift_backup_$(date +%Y%m%d_%H%M%S)
fi

# Create new venv with Python 3.11
echo "Creating new virtual environment with Python 3.11..."
python3.11 -m venv lift

# Activate
source lift/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install packages
echo "Installing required packages..."
pip install opencv-python mediapipe firebase-admin google-generativeai numpy

# Verify MediaPipe
echo ""
echo "========================================"
echo "Verification:"
echo "========================================"
python -c "import mediapipe as mp; print(f'MediaPipe version: {mp.__version__}'); print(f'Has solutions: {hasattr(mp, \"solutions\")}')"

echo ""
echo "✓ Done! Your environment is ready."
echo ""
echo "To activate in future sessions:"
echo "  source lift/bin/activate"
echo ""
echo "To run your app:"
echo "  python app.py"
