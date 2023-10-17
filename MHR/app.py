from flask import Flask, request, render_template, jsonify, session

import csv
import math

predefined_weapons = []

# Read the CSV file into predefined_weapons list
with open('lances.csv', mode='r') as file:
    reader = csv.DictReader(file)
    for row in reader:
        row['raw'] = float(row['raw'])  # Convert to float
        row['element'] = float(row['element'])  # Convert to float
        # sharpness remains a string
        predefined_weapons.append(row)


app = Flask(__name__)
app.secret_key = 'some_secret_key'

# Include the calculator functions and data here
# For example, calculate_total_raw, calculate_total_element, etc.

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Extract form data from POST request
        selected_weapon = request.form.get('predefined_weapon')
        if selected_weapon != 'none':
            weapon_data = next(w for w in predefined_weapons if w['name'] == selected_weapon)
            session.update(weapon_data)
        else:
            session['raw'] = float(request.form.get('raw'))
            session['element'] = float(request.form.get('element'))
            session['sharpness'] = request.form.get('sharpness')

        session['critical_boost_level'] = int(request.form.get('critical_boost_level'))
        session['motion_value'] = float(request.form.get('motion_value'))
        session['raw_hit_zone'] = float(request.form.get('raw_hit_zone'))
        session['element_hit_zone'] = float(request.form.get('element_hit_zone'))
        session['critical_chance'] = float(request.form.get('critical_chance'))

        # Perform calculations using the calculator function
        results = monster_hunter_calculator(session)

        # Render the results in an HTML template
        return render_template('results.html', results=results)

    return render_template('index.html', predefined_weapons=predefined_weapons)

# Update the function to include the "Expected Sum of Damage over 100 Attacks"
def monster_hunter_calculator(session):
    """Perform calculations based on user inputs and return the results."""
    # Extract data from the session

    raw = session['raw']
    element = session['element']
    sharpness = session['sharpness']
    critical_boost_level = session['critical_boost_level']
    motion_value = session['motion_value']
    raw_hit_zone = session['raw_hit_zone']
    element_hit_zone = session['element_hit_zone']
    critical_chance = session['critical_chance'] / 100


    # Perform calculations
    total_raw = calculate_total_raw(raw, sharpness, motion_value, raw_hit_zone)
    total_element = calculate_total_element(element, sharpness, motion_value, element_hit_zone)
    display_damage = calculate_displayed_damage(total_raw, total_element)
    critical_damage = calculate_critical_damage(total_raw, critical_boost_level)
    # average_damage = calculate_average_damage(displayed_damage, total_raw, critical_chance, critical_boost_level)
    average_damage_per_hit, expected_sum_damage_100_attacks = calculate_average_damage(
    display_damage, critical_damage, critical_chance
)
    # # Calculate the expected sum of damage over 100 attacks
    # expected_sum_damage = average_damage * 100
    
    # Prepare and return the results
    results = {
        "total_raw": math.floor(total_raw),
        "total_element": math.floor(total_element),
        "displayed_damage": math.floor(display_damage),
        "critical_damage": math.floor(critical_damage),
        "average_damage": math.floor(average_damage_per_hit),
        "expected_sum_damage": math.floor(expected_sum_damage_100_attacks)
    }
    
    return results

# Define a dictionary to store weapon details
# This can be expanded later to store multiple weapons
weapon_data = {
    'raw': 100,
    'element': 10,
    'sharpness': 'Blue'
}

# Sharpness values mapping
raw_sharpness_values = {
    'Blue': 1.2,
    'White': 1.32,
    'Purple': 1.39
}

element_sharpness_values = {
    'Blue': 1.0625,
    'White': 1.15,
    'Purple': 1.25
}

def calculate_total_raw(raw, sharpness, motion_value, raw_hit_zone):
    """Calculate the Total Raw Damage"""
    return raw * raw_sharpness_values[sharpness] * motion_value * raw_hit_zone

def calculate_total_element(element, sharpness, motion_value, element_hit_zone):
    """Calculate the Total Element Damage"""
    return element * element_sharpness_values[sharpness] * motion_value * element_hit_zone

def calculate_displayed_damage(total_raw, total_element):
    """Calculate the Displayed Damage"""
    return total_raw + total_element

# Define a function to calculate critical damage
def calculate_critical_damage(total_raw, critical_boost_level):
    """Calculate the Critical Damage"""
    # Define critical boost multipliers
    critical_boost_multipliers = {
        0: 1.25,
        1: 1.3,
        2: 1.35,
        3: 1.4
    }
    
    return total_raw * critical_boost_multipliers[critical_boost_level]

# Define a function to calculate average damage over 100 attacks
# def calculate_average_damage(displayed_damage, total_raw, critical_chance, critical_boost_level):
#     """Calculate the Average Damage over 100 attacks"""
#     critical_damage = calculate_critical_damage(total_raw, critical_boost_level)
    
#     # Calculate the average raw damage
#     avg_raw = (1 - critical_chance) * total_raw + critical_chance * critical_damage
    
#     return displayed_damage - total_raw + avg_raw
def calculate_average_damage(display_damage, critical_damage, critical_chance):
    # Calculate the average damage per hit
    average_damage_per_hit = (critical_chance * critical_damage) + ((1 - critical_chance) * display_damage)
    
    # Calculate the expected sum of damage over 100 attacks
    expected_sum_damage_100_attacks = average_damage_per_hit * 100
    
    return average_damage_per_hit, expected_sum_damage_100_attacks



if __name__ == '__main__':
    app.run(debug=True)

