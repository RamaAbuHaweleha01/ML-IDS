#!/bin/bash
# test_setup.sh - Quick test of ML-IDS setup

echo "Testing ML-IDS setup..."
echo "======================"

# Check directories
echo "Checking directories..."
for dir in logs models config data; do
    if [ -d "$dir" ]; then
        echo "✓ $dir exists"
    else
        echo "✗ $dir missing"
    fi
done

# Check model files
echo -e "\nChecking model files..."
for file in models/randomforest_ids.pkl models/scaler.pkl models/label_encoder.pkl; do
    if [ -f "$file" ]; then
        echo "✓ $file exists"
    else
        echo "✗ $file missing"
    fi
done

# Check config file
echo -e "\nChecking config file..."
if [ -f "config/config.yaml" ]; then
    echo "✓ config/config.yaml exists"
    # Show first few lines
    echo "Config preview:"
    head -20 config/config.yaml
else
    echo "✗ config/config.yaml missing"
fi

# Check Python files
echo -e "\nChecking Python modules..."
for file in config.py packet_capture.py feature_extractor.py ml_predictor.py alert_handler.py ids_service.py; do
    if [ -f "$file" ]; then
        echo "✓ $file exists"
    else
        echo "✗ $file missing"
    fi
done

echo -e "\nSetup test complete!"
echo "To run the IDS: python3 ids_service.py"
