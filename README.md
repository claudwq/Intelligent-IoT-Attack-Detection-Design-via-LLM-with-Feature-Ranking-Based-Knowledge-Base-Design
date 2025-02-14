# Intelligent-IoT-Attack-Detection-Design-via-LLM-with-Feature-Ranking-Based-Knowledge-Base-Design
This repository contains the code and datasets for our paper "Intelligent IoT Attack Detection Design via LLM with Feature Ranking-Based Knowledge Base Design," submitted to GenAI@Edge: Empowering Generative AI at the Edge in conjunction with the 2025 AAAI Spring Symposium Series. This work introduces a novel on-device IoT attack detection framework, leveraging large language models (LLMs) and a feature ranking-based Knowledge Base (KB) design to enhance detection efficiency on resource-constrained edge devices.

Key Features
Feature Ranking with Random Forest Regressor (RFR): Identifies the most critical features for effective attack classification.
Knowledge Base Construction: Implements both long and short KB designs to optimize model complexity and detection accuracy.
On-Device Large Language Models (ODLLMs): Evaluates Llama 3.2 3B, Phi3 Mini 3.8B, and Llama 3.1 8B for attack classification.
DDoS Attack Detection: Detects multiple attack types, including ICMP, UDP, TCP, and PSHACK floods, using the CICIoT 2023 dataset.
Optimized for Edge Deployment: Enables real-time, resource-efficient IoT security solutions.
Repository Contents
📄 Paper: Preprint or published version of the research paper.
📝 Codebase: Implementation of the attack detection framework.
📊 Dataset: Processed network traffic data from CICIoT 2023.
🔍 Experiments: Accuracy comparisons for different KB designs and models.
📖 Documentation: Setup instructions for running the detection framework.
Installation & Usage
To run the attack detection framework, follow these steps:

bash
Copy
Edit
git clone [https://github.com/your-repo/IoT-LLM-Attack-Detection.git  ](https://github.com/claudwq/Intelligent-IoT-Attack-Detection-Design-via-LLM-with-Feature-Ranking-Based-Knowledge-Base-Design.git)
cd IoT-LLM-Attack-Detection  
pip install -r requirements.txt  
python main.py  
Refer to the README for detailed setup instructions.

Results & Performance
Our experiments demonstrate that tailored KB designs significantly enhance detection accuracy, particularly for smaller LLMs. The short KB improves model performance by reducing redundant information while retaining critical features for classification.

Citation
If you find this work useful, please consider citing our paper:

bibtex
Copy
Edit
@inproceedings{verma2025iot,
  title={Intelligent IoT Attack Detection Design via LLM with Feature Ranking-Based Knowledge Base Design},
  author={Verma, Satvik and Wang, Qun and Bethel, E. Wes},
  booktitle={GenAI@Edge: Empowering Generative AI at the Edge, AAAI Spring Symposium},
  year={2025}
}
Contributors
Satvik Verma (Affiliation)
Qun Wang (San Francisco State University)
E. Wes Bethel (Affiliation)
License
This project is licensed under the MIT License (or specify another license).
