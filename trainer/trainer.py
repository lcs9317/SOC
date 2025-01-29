# File: trainer/trainer.py
import os
import sys
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, Conv1D, GlobalMaxPooling1D

def main():
    # 모델 유형 파라미터
    model_type = "lstm"
    if len(sys.argv) > 1:
        model_type = sys.argv[1].lower()

    # 1) CSV 로드 (CIC-DDoS2019)
    dataset_path = "/app/datasets/DDoS2019.csv"
    df = pd.read_csv(dataset_path)

    # 2) Label(타겟) -> 0,1 변환
    #    CSV에 " Label"로 되어 있을 가능성이 큼 (앞에 공백)
    df[' Label'] = (df[' Label'] != 'BENIGN').astype(int)

    # 3) 학습에 쓰지 않을 컬럼들(Flow ID, IP, Port, Timestamp 등) drop
    drop_cols = [
        'Flow ID',' Source IP',' Source Port',' Destination IP',' Destination Port',' Protocol',
        ' Timestamp'
    ]
    df = df.drop(columns=drop_cols, errors='ignore')

    # 4) X, y 분리
    y = df[' Label'].values
    X = df.drop(columns=[' Label'], errors='ignore').values

    # NaN/inf -> 0
    X = np.nan_to_num(X, nan=0, posinf=0, neginf=0)

    # 5) Train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y,
                                                        test_size=0.2,
                                                        random_state=42)

    # 6) 스케일링
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # 7) 모델 정의
    if model_type == 'cnn':
        X_train = X_train.reshape((X_train.shape[0], X_train.shape[1], 1))
        X_test  = X_test.reshape((X_test.shape[0], X_test.shape[1], 1))

        model = Sequential([
            Conv1D(64, kernel_size=3, activation='relu', input_shape=(X_train.shape[1], 1)),
            GlobalMaxPooling1D(),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ])
    else:
        X_train = X_train.reshape((X_train.shape[0], 1, X_train.shape[1]))
        X_test  = X_test.reshape((X_test.shape[0], 1, X_test.shape[1]))

        model = Sequential([
            LSTM(64, input_shape=(1, X_train.shape[2])),
            Dropout(0.2),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    # 8) 학습
    model.fit(X_train, y_train, epochs=5, batch_size=32,
              validation_split=0.2, verbose=1)

    # 9) 평가
    y_pred = (model.predict(X_test) > 0.5).astype(int)
    print(classification_report(y_test, y_pred))

    # 10) 모델 저장
    if model_type == 'cnn':
        model_save_path = "/app/models/ddos_cnn_model.h5"
    else:
        model_save_path = "/app/models/ddos_model.h5"

    scaler_save_path = "/app/models/scaler.pkl"
    model.save(model_save_path)
    joblib.dump(scaler, scaler_save_path)
    print(f"모델 저장 완료: {model_save_path}, {scaler_save_path}")

if __name__ == "__main__":
    main()
