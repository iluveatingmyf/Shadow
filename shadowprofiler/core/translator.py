# core/translator.py
class SemanticTranslator:
    @staticmethod
    def to_physical_state(service):
        # 简单映射，实际实验中不需要
        return service
    @staticmethod
    def get_reverse_state(state):
        return state