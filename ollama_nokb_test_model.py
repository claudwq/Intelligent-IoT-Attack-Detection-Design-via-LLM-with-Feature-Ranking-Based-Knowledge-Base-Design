import json
import re
import pandas as pd
import ollama  


feature_names = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration", "Rate", "Srate", "Drate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count", "fin_count", "urg_count",
    "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP",
    "ARP", "ICMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number",
    "Magnitue", "Radius", "Covariance", "Variance", "Weight", "label"
]


df = pd.read_csv('without_syn.csv', header=None, names=feature_names)
filtered_df = df[df['label'].isin(['DDoS-ICMP_Flood', 'DDoS-UDP_Flood', 'DDoS-TCP_Flood', 'DDoS-PSHACK_Flood', 'DDoS-SYN_Flood', 'DDoS-RSTFINFlood', 'DDoS-SynonymousIP_Flood'])]


attack_types_list = ['DDoS-ICMP_Flood', 'DDoS-UDP_Flood', 'DDoS-TCP_Flood', 'DDoS-PSHACK_Flood', 'DDoS-SYN_Flood', 'DDoS-RSTFINFlood', 'DDoS-SynonymousIP_Flood']
attack_types_str = ', '.join(attack_types_list)


def generate_prediction(data):
    input_text = (
        f"Given the following network traffic data: {json.dumps(data)}, "
        f"what is the most likely type of attack? Choose one from the following list: {attack_types_str}. "
        "Provide the answer in the format: 'The attack type is ...'."
    )
    
    response = ollama.generate(model="llama3.2", prompt=input_text)
    
    #return response["content"] if response else "Error generating response"
    # if response and 'content' in response:
    #     return response['content']
    # else:
    #     return "Error: Response did not contain content"
    
    
    if response and 'response' in response:
        return response['response']
    else:
        return "Error: Response did not contain content"

normalized_attack_types_list = [label.lower().replace("-", "").replace("_", "") for label in attack_types_list]


correct_predictions_per_label = {label: 0 for label in normalized_attack_types_list}
incorrect_predictions_per_label = {label: 0 for label in normalized_attack_types_list}

for index, row in filtered_df.iterrows():
    data = row.to_dict()
    true_label = str(data.pop("label"))  # Convert true_label to a string

    normalized_true_label = true_label.lower().replace("-", "").replace("_", "")
    try:
        response_content = generate_prediction(data)
        match = re.search(r"The attack type is (.+)\.", response_content)
        predicted_label = match.group(1).strip().lower().replace("-", "").replace("_", "") if match else ""

        # Check if the predicted attack type matches the true label
        if normalized_true_label == predicted_label:
            correct_predictions_per_label[normalized_true_label] += 1
            print(f"Sample {index + 1}: Correct prediction. Predicted: {response_content.strip()}")
        else:
            incorrect_predictions_per_label[normalized_true_label] += 1
            print(f"Sample {index + 1}: Incorrect prediction. Predicted: {response_content.strip()}, Expected: {true_label}")
    
    except Exception as e:
        print(f"Sample {index + 1}: Error processing the request. Exception: {str(e)}")
        incorrect_predictions_per_label[normalized_true_label] += 1

    #print("\n" + "="*50 + "\n")

# Print the final results
total_samples = len(df)
print(f"Total Samples: {total_samples}")

for label in normalized_attack_types_list:
    total_label_samples = correct_predictions_per_label[label] + incorrect_predictions_per_label[label]
    if total_label_samples > 0:
        accuracy = (correct_predictions_per_label[label] / total_label_samples) * 100
        print("llama3.2 3B without kb")
        print(f"Label: {label}")
        print(f"  Total Samples: {total_label_samples}")
        print(f"  Correct Predictions: {correct_predictions_per_label[label]}")
        print(f"  Incorrect Predictions: {incorrect_predictions_per_label[label]}")
        print(f"  Accuracy: {accuracy:.2f}%")
    else:
        print(f"Label: {label} has no samples.")