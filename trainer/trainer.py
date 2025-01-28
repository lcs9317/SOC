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
    # 간단히 model_type 인자 받기 (기본값: lstm)
    model_type = "lstm"
    if len(sys.argv) > 1:
        model_type = sys.argv[1].lower()

    # 1) 데이터 로드
    dataset_path = "/app/datasets/DDoS2019.csv"
    df = pd.read_csv(dataset_path)
    df[' Label'] = (df[' Label'] != 'BENIGN').astype(int)
    drop_cols = ['Flow ID',' Source IP',' Source Port',' Destination IP',' Destination Port',' Timestamp']
    df = df.drop(columns=drop_cols, errors='ignore')

    X = df.drop(columns=[' Label'], errors='ignore').values
    y = df[' Label'].values
    X = np.nan_to_num(X, nan=0, posinf=0, neginf=0)

    scaler = StandardScaler()
    X = scaler.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2,random_state=42)

    # 2) 모델 정의
    if model_type == 'cnn':
        # CNN 예시
        X_train = X_train.reshape((X_train.shape[0], X_train.shape[1], 1))  # (batch, features, channel=1)
        X_test = X_test.reshape((X_test.shape[0], X_test.shape[1], 1))

        model = Sequential([
            Conv1D(64, kernel_size=3, activation='relu', input_shape=(X_train.shape[1], 1)),
            GlobalMaxPooling1D(),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ])
    else:
        # LSTM 예시
        X_train = X_train.reshape((X_train.shape[0], 1, X_train.shape[1]))
        X_test = X_test.reshape((X_test.shape[0], 1, X_test.shape[1]))

        model = Sequential([
            LSTM(64, input_shape=(1, X_train.shape[2])),
            Dropout(0.2),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.fit(X_train, y_train, epochs=5, batch_size=32, validation_split=0.2, verbose=1)

    y_pred = (model.predict(X_test) > 0.5).astype(int)
    print(classification_report(y_test, y_pred))

    # 모델 저장
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
