def compute_privacy_score(self, k, t):
    """
    Compute a privacy score based on k-anonymity & t-closeness.
    Higher values indicate stronger privacy.
    """
    k_score = min(k / self.__numberOfTracesOriginal, 1.0)  # Normalize k
    t_score = 1.0 - t  # Inverse of t-closeness for scoring
    return (k_score + t_score) / 2