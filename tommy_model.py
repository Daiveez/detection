# %%
import numpy as np 
import pandas as pd 
import matplotlib.pyplot as plt 
import seaborn as sns 
import sklearn 
import joblib
from sklearn.tree import DecisionTreeClassifier
from sklearn import metrics 
from sklearn.model_selection import train_test_split , KFold , GridSearchCV
from sklearn.impute import SimpleImputer 
from sklearn.preprocessing import OrdinalEncoder


# %%
#file_path = '/Users/user/Downloads/cybersecurity_intrusion_data.csv'
#dataset = pd.read_csv(file_path)


# %%
file_path = '/Users/user/Downloads/cybersecurity_intrusion_data.csv'
dataset = pd.read_csv(file_path)

# Define criteria for threat levels
def assign_threat_level(row):
    if (row['login_attempts'] <= 3 and row['failed_logins'] <= 1 and row['session_duration'] <= 300):
        return 'Low'
    elif (row['login_attempts'] <= 5 and row['failed_logins'] <= 3 and row['session_duration'] <= 600):
        return 'Medium'
    else:
        return 'High'

# Add the threat_level column
dataset['threat_level'] = dataset.apply(assign_threat_level, axis=1)

# Save the updated dataset
dataset.to_csv('/Users/user/Downloads/cybersecurity_intrusion_data_with_threat_level.csv', index=False)


# %%
imp = SimpleImputer(strategy='most_frequent')
dataset['encryption_used'] = imp.fit_transform(dataset[['encryption_used']]).ravel()



# %%
original_sessionID = dataset["session_id"].unique().tolist()
original_protocol = dataset["protocol_type"].unique().tolist()
original_encryption = dataset["encryption_used"].unique().tolist()
original_browser = dataset["browser_type"].unique().tolist()
original_threat = dataset["threat_level"].unique().tolist()




# %%
dataset = dataset.drop(['session_id'], axis = 1)

# %%
ore=OrdinalEncoder()
for column in dataset.columns:
    if dataset[column].dtype=='object':
        dataset[column]=ore.fit_transform(dataset[[column]])



# %%
#dataset['network_packet_size'].quantile(0.995)

# %%
#min_threshold,max_threshold=dataset['session_duration'].quantile([0,0.93])


# %%
#dataset=dataset[(dataset.session_duration<max_threshold) & (dataset.session_duration>min_threshold)]


# %%
for column in dataset['session_duration']:
    first=dataset['session_duration'].quantile(0)
    second=dataset['session_duration'].quantile(0.93)
    dataset.loc[dataset['session_duration'] < first, 'session_duration'] = first
    dataset.loc[dataset['session_duration'] > second, 'session_duration'] = second

# %%
for column in dataset['network_packet_size']:
    firs=dataset['network_packet_size'].quantile(0)
    secon=dataset['network_packet_size'].quantile(0.995)
    dataset.loc[dataset['network_packet_size'] < firs, 'network_packet_size'] = firs
    dataset.loc[dataset['network_packet_size'] > secon, 'network_packet_size'] = secon


# %%
dataset['ip_reputation_score'].quantile(0.995)

# %%
for column in dataset['ip_reputation_score']:
    fir=dataset['ip_reputation_score'].quantile(0)
    seco=dataset['ip_reputation_score'].quantile(0.995)
    dataset.loc[dataset['ip_reputation_score'] < fir, 'ip_reputation_score'] = fir
    dataset.loc[dataset['ip_reputation_score'] > seco, 'ip_reputation_score'] = seco

# %%
x = dataset[['login_attempts','session_duration','failed_logins','browser_type','unusual_time_access']]
y = dataset['attack_detected']

# %%
x_train,x_test,y_train,y_test = train_test_split(x,y,test_size=0.3,random_state=0)

# %%
def get_score(model,x_train,x_test,y_train,y_test):
    model.fit(x_train,y_train)
    y_pred=model.predict(x_test)
    return model.score(x_test,y_test)

# %%
kf=KFold(n_splits=5)


# %%
score_tree =[]
for train_index,test_index in kf.split(x):
    x_train,x_test=x.iloc[train_index],x.iloc[test_index]
    y_train,y_test=y.iloc[train_index],y.iloc[test_index]
    
    score_tree.append((get_score(DecisionTreeClassifier(),x_train,x_test,y_train,y_test)))


# %%
'''from sklearn.model_selection import GridSearchCV

# Define the parameter grid
param_grid = {
    'criterion': ['gini', 'entropy'],
    'max_depth': [3, 5, 10, 15, 20],
    'min_samples_split': [2, 5, 10, 15],
    'min_samples_leaf': [1, 2, 5, 10],
    'max_features': ['sqrt', 'log2', None]
}

# Initialize Decision Tree model
dt = DecisionTreeClassifier()

# Perform Grid Search
grid_search = GridSearchCV(dt, param_grid, cv=5, scoring='accuracy')
grid_search.fit(x_train, y_train)

# Best parameters
print("Best Parameters:", grid_search.best_params_)

'''
# %%
ddt = DecisionTreeClassifier(
    criterion = 'gini',
    max_depth = 5,
    max_features = None,
    min_samples_leaf = 1,
    min_samples_split = 2
)
ddt.fit(x_train,y_train)
ppd = ddt.predict(x_test)
metrics.accuracy_score(ppd,y_test)

# %%
joblib.dump(ddt, 'tommy_model.pkl')
joblib.dump(original_sessionID, 'original_sessionID.pkl')
joblib.dump(original_protocol, 'original_protocol.pkl')
joblib.dump(original_encryption, 'original_encryption.pkl')
joblib.dump(original_browser, 'original_browser.pkl')
joblib.dump(original_threat, 'original_threat.pkl')

# %%


# %%



